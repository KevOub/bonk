package main

import (
	"bufio"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"

	"github.com/elastic/go-libaudit/rule"
	"github.com/elastic/go-libaudit/rule/flags"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/fatih/color"
)

var (
	fs           = flag.NewFlagSet("audit", flag.ExitOnError)
	diag         = fs.String("diag", "logs", "dump raw information from kernel to file")
	mode         = fs.String("mode", "load", "[load/bonk/list] choose between\n>'load' (load rules)\n>'mode' (bonk processes)\n>'list' (list rules in kernel)\n")
	rate         = fs.Uint("rate", 0, "rate limit in kernel (default 0, no rate limit)")
	backlog      = fs.Uint("backlog", 8192, "backlog limit")
	immutable    = fs.Bool("immutable", false, "make kernel audit settings immutable (requires reboot to undo)")
	receiveOnly  = fs.Bool("ro", false, "receive only using multicast, requires kernel 3.16+")
	verbose      = fs.Bool("v", true, "whether to print to stdout or not")
	colorEnabled = fs.Bool("color", true, "whether to use color or not")
	ptraceKill   = fs.Bool("ptrace", false, "use ptrace trolling to kill process rudely")
	configPath   = fs.String("config", "config.json", "where custom config is located")
	showInfo     = fs.Bool("info", true, "whether to show informational warnings or just bonks")
	cf           = Config{}
	//go:embed good.rules
	res embed.FS
)

// // go:embed 43-module-load.rules
// var embededRules embed.FS

const (
	// RULESPATH = "/etc/audit/rules.d/audit.rules"
	CONFIGPATH = "/var/bonk/config.json"
	// RULESPATH = "/etc/audit/rules.d/audit.rules"
	LOGSPATH = "/var/log/bonk/bonk.log"
)

func main() {
	user, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	if user.Username != "root" {
		log.Fatal("not root!")
	}

	fs.Parse(os.Args[1:])
	// color magic
	if !*colorEnabled {
		color.NoColor = true
	}

	// set up logging
	logFile, err := os.OpenFile(LOGSPATH, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		panic(err)
	}
	// only log when in bonk mode
	if *verbose && *mode == "bonk" {
		mw := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
	} else {
		log.SetOutput(logFile)
	}

	// load configuration file
	cf.Load(*configPath)

	if err := read(); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func ruleAddWrapper(rule2add string, r *libaudit.AuditClient) error {

	ru, err := flags.Parse(rule2add)
	if err != nil {
		return err
	}

	// convert
	actualBytes, err := rule.Build(ru)
	if err != nil {
		return err
	}

	r.WaitForPendingACKs()

	if err = r.AddRule([]byte(actualBytes)); err != nil {
		return fmt.Errorf("failed to add rule:\n %w", err)
	}

	return nil
}

func read() error {
	if os.Geteuid() != 0 {
		return errors.New("you must be root to receive audit data")
	}

	// Write netlink response to a file for further analysis or for writing
	// tests cases.
	var diagWriter io.Writer
	if *diag != "" {
		f, err := os.OpenFile(*diag, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		diagWriter = f
	}

	log.Println("starting netlink client")

	var err error
	var client *libaudit.AuditClient
	if *receiveOnly {
		client, err = libaudit.NewMulticastAuditClient(diagWriter)
		if err != nil {
			return fmt.Errorf("failed to create receive-only audit client: %w", err)
		}
		defer client.Close()
	} else {
		client, err = libaudit.NewAuditClient(diagWriter)
		if err != nil {
			return fmt.Errorf("failed to create audit client: %w", err)
		}
		defer client.Close()

		status, err := client.GetStatus()
		if err != nil {
			return fmt.Errorf("failed to get audit status: %w", err)
		}
		log.Printf("received audit status=%+v", status)

		if status.Enabled == 0 {
			log.Println("enabling auditing in the kernel")
			if err = client.SetEnabled(true, libaudit.WaitForReply); err != nil {
				return fmt.Errorf("failed to set enabled=true: %w", err)
			}
		}

		if status.RateLimit != uint32(*rate) {
			log.Printf("setting rate limit in kernel to %v", *rate)
			if err = client.SetRateLimit(uint32(*rate), libaudit.NoWait); err != nil {
				return fmt.Errorf("failed to set rate limit to unlimited: %w", err)
			}
		}

		if status.BacklogLimit != uint32(*backlog) {
			log.Printf("setting backlog limit in kernel to %v", *backlog)
			if err = client.SetBacklogLimit(uint32(*backlog), libaudit.NoWait); err != nil {
				return fmt.Errorf("failed to set backlog limit: %w", err)
			}
		}

		// do **not** want to enable immutable kernel **yet**
		// if status.Enabled != 2 {
		// 	log.Printf("setting kernel settings as immutable")
		// 	if err = client.SetImmutable(libaudit.NoWait); err != nil {
		// 		return fmt.Errorf("failed to set kernel as immutable: %w", err)
		// 	}
		// }

		log.Printf("sending message to kernel registering our PID (%v) as the audit daemon", os.Getpid())
		if err = client.SetPID(libaudit.NoWait); err != nil {
			return fmt.Errorf("failed to set audit PID: %w", err)
		}

	}

	if *mode == "load" {
		return load(client)
	} else if *mode == "bonk" {
		return receive(client)
	} else {
		flag.PrintDefaults()
		return fmt.Errorf("please specify which mode to use")
	}

}

// command to load our rules
func load(r *libaudit.AuditClient) error {
	data, _ := res.Open("good.rules")

	scanner := bufio.NewScanner(data)
	for scanner.Scan() {
		if rule2add := scanner.Text(); !strings.HasPrefix(rule2add, "#") && rule2add != "" {
			fmt.Printf("rule> %s\n", rule2add)
			err := ruleAddWrapper(rule2add, r)
			// r.WaitForPendingACKs()
			if err != nil {
				fmt.Printf("error> %s\n", err)
			}

		}

	}

	for _, rule := range cf.Rules {
		if strings.HasPrefix(rule, "#") && rule != "" {
			err := ruleAddWrapper(rule, r)
			// r.WaitForPendingACKs()
			if err != nil {
				fmt.Printf("error> %s\n", err)
			}
		}
	}

	fmt.Println(r.GetRules())
	return nil
}

func runCMD(command, flavortext string) {
	byteCommand := strings.Split(command, " ") // splits into bytes seperated by spaces
	_, err := exec.Command(byteCommand[0], byteCommand[1:]...).Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			log.Fatalf("%s\n%s", flavortext, err)
		}
	}
}

func bonkProc(a AuditMessageBonk, prev string) (string, error) {

	var outMessage string
	// if the offense is bonkable
	if cf.IsBonkable(a.Key) {
		// and the user is *not* allowed
		if !cf.AllowedUser(a.AuidHumanReadable) {
			// bonk the process!

			// if *ptraceKill {
			// 	go func() {
			// 		/*
			// 			DO NOT SCREW WITH THIS. THIS IS **EVIL** AND WILL BREAK THINGS
			// 			YOU ARE INTERCEPTING THE PROCESSES WILLY NILLY IN GOROUTINES AND SEEING WHAT HAPPENS
			// 			WHAT POSSIBLY COULD GO WRONG???
			// 		*/
			// 		pid2int, _ := strconv.Atoi(a.Pid)
			// 		proc, _ := os.FindProcess(pid2int)
			// 		syscall.PtraceAttach(proc.Pid)
			// 		syscall.PtraceSyscall(proc.Pid, 0)
			// 		time.Sleep(1 * time.Second)
			// 		syscall.Wait4(proc.Pid, nil, 0, nil)
			// 		syscall.PtraceDetach(proc.Pid)
			// 		syscall.Kill(proc.Pid, syscall.SIGKILL)
			// 	}()
			// } else {
			// commandBuilder := fmt.Sprintf("kill -9 %s", a.Pid)
			// runCMD(commandBuilder, "failed to kill a pid")
			syscall.Kill(a.Pid, syscall.SIGKILL)
			// currentTime := float64(time.Now().UnixNano()) / float64(time.Second)
			// if s, err := strconv.ParseFloat(a.Timestamp, 64); err == nil {
			// 	fmt.Printf("TIMENOW: %f TIMESTAMP: %s\n", currentTime, a.Timestamp)
			// 	fmt.Printf("TIME DELTA: %f\n", float64(currentTime)-s)
			// }
			// }

			outMessage = fmt.Sprintf("[%s] USER:%s\t;KEY %s\t; CMD: %s;\tCMD_F: %s;\t", color.RedString("BONK"),
				color.RedString(a.AuidHumanReadable), color.RedString(a.Key),
				color.RedString(a.Exe), color.RedString(a.Proctile),
			)
			if prev != outMessage {
				log.Print(outMessage)
			}
			return outMessage, nil
		} else { // otherwise the user is allowed
			outMessage = fmt.Sprintf("[%s] USER:%s\t;KEY %s\t; CMD: %s;\tCMD_F: %s;\t", color.HiMagentaString("CRIT"),
				color.HiMagentaString(a.AuidHumanReadable), color.HiMagentaString(a.Key),
				color.HiMagentaString(a.Exe), color.HiMagentaString(a.Proctile),
			)

			if prev != outMessage {
				log.Print(outMessage)
			}
			return outMessage, nil
		}

	} else {
		// only log notable events
		if a.Key != "" {
			// then the message is not bonkable
			if *showInfo {
				outMessage = fmt.Sprintf("[%s] USER:%s\t;KEY %s\t; CMD: %s;\tCMD_F: %s;\t", color.BlueString("INFO"),
					color.BlueString(a.AuidHumanReadable), color.BlueString(a.Key),
					color.BlueString(a.Exe), color.BlueString(a.Proctile),
				)
				if outMessage != prev {
					log.Print(outMessage)
				}
				return outMessage, nil

			}
		}

	}
	return "", nil
}

// watch output
func receive(r *libaudit.AuditClient) error {

	var a AuditMessageBonk
	prevMessage := ""

	// var outMessagePrev string
	for {

		rawEvent, err := r.Receive(false)
		if err != nil {
			return fmt.Errorf("receive failed: %w", err)
		}

		// Messages from 1300-2999 are valid audit messages.
		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}

		// THIS IS THE BONK LOGIC
		// fmt.Printf("type=%v msg=%v\n", rawEvent.Type, string(rawEvent.Data))

		if a.IsNewAuditID(string(rawEvent.Data)) {
			// so this is a new audit message
			// bonk the cumulative message
			prevMessage, _ = bonkProc(a, prevMessage)
			// then make new audit message
			a = AuditMessageBonk{}
			err := a.InitAuditMessage(string(rawEvent.Data))
			if err != nil && *verbose {
				fmt.Print(err)
			}
		} else {
			// otherwise just append to audit class
			err := a.InitAuditMessage(string(rawEvent.Data))
			if err != nil && *verbose {
				fmt.Print(err)
			}
		}

	}
}
