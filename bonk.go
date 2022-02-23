package main

import (
<<<<<<< HEAD
	"bufio"
	"embed"
	"errors"
=======
	_ "embed"
	"encoding/json"
>>>>>>> master
	"flag"
	"fmt"
	"io"
	"log"
	"os"
<<<<<<< HEAD
=======
	"os/exec"
>>>>>>> master
	"os/user"
	"strings"
	"syscall"

<<<<<<< HEAD
	"github.com/elastic/go-libaudit/rule"
	"github.com/elastic/go-libaudit/rule/flags"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/fatih/color"
)

var (
	fs          = flag.NewFlagSet("bonk", flag.ExitOnError)
	diag        = fs.String("diag", "logs", "dump raw information from kernel to file")
	rate        = fs.Uint("rate", 0, "rate limit in kernel (default 0, no rate limit)")
	backlog     = fs.Uint("backlog", 8192, "backlog limit")
	receiveOnly = fs.Bool("ro", false, "receive only using multicast, requires kernel 3.16+")
	// immutable    = fs.Bool("immutable", false, "make kernel audit settings immutable (requires reboot to undo)")
	mode         = fs.String("mode", "load", "[load/bonk/list] choose between\n>'load' (load rules)\n>'bonk' (bonk processes)\n>'honk' (just honk no bonk)\n>'list' (list rules in kernel)\n")
	verbose      = fs.Bool("v", true, "whether to print to stdout or not")
	colorEnabled = fs.Bool("color", true, "whether to use color or not")
	// ptraceKill   = fs.Bool("ptrace", false, "use ptrace trolling to kill process rudely")
	configPath = fs.String("config", "", "where custom config is located")
	showInfo   = fs.Bool("info", true, "whether to show informational warnings or just bonks")
	cf         = Config{}
	RawLogger  *log.Logger
	CoolLogger *log.Logger
	//go:embed embed/good.rules
	//go:embed embed/bonk.art
	//go:embed embed/config.json
	res embed.FS
)

// // go:embed 43-module-load.rules
// var embededRules embed.FS

const (
	// RULESPATH = "/etc/audit/rules.d/audit.rules"
	CONFIGPATH = "/etc/bonk/config.json"
	// RULESPATH = "/etc/bonk/config"
	LOGSPATH     = "/var/log/bonk/bonk.log"
	LOGSRAWPATH  = "/var/log/bonk/bonk-verbose.log"
	LOGSCOOLPATH = "/var/log/bonk/bonk-cool.log"
)
=======
	"github.com/fatih/color"
	"github.com/nxadm/tail"
)

var (
	RULESPATH = "/etc/audit/rules.d/audit.rules"
	LOGSPATH  = "/var/log/audit/audit.log"
)

//go:embed good.rules
var embeddedRules []byte

//go:embed bonk.art
var bonkArt []byte

// turns regex rule to human readable

func embedOurRules(rulesPath string) {
	// os.O_TRUNC empties the file on opening
	// currentRules, err := os.OpenFile(RULESPATH, os.O_TRUNC, 0777)
	currentRules, err := os.OpenFile(rulesPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0777)
	if err != nil {
		log.Fatalf("Failed to open operating system rules.\n%s", err)
	}
	defer currentRules.Close()

	_, err = currentRules.Write(embeddedRules)
	if err != nil {
		log.Fatalf("Failed to open operating system rules.\n%s", err)
	}
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

func clearLogs(logsPath string) {
	f, err := os.OpenFile(logsPath, os.O_TRUNC, 0777)
	if err != nil {
		log.Fatalf("Failed to yeet the contents of %s:%v", logsPath, err)
	}
	f.Truncate(0)
	stat, err := f.Stat()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(stat.Size())
	f.Close()
}

func PrettyStruct(data interface{}) (string, error) {
	val, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return "", err
	}
	return string(val), nil
}
>>>>>>> master

func init() {
	// set up logging
	logFile, err := os.OpenFile(LOGSPATH, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	CoolLogger = log.New(logFile, "", log.Ltime|log.Lshortfile)

	// only log when in bonk mode
	if *mode == "bonk" {
		mw := io.MultiWriter(os.Stdout, logFile)
		CoolLogger.SetOutput(mw)
	} else {
		CoolLogger.SetOutput(logFile)
	}

	RawLogger = log.New(logFile, "", log.Lshortfile)

	logRawFile, err := os.OpenFile(LOGSRAWPATH, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	RawLogger.SetOutput(logRawFile)

	// create /var/bonk & /etc/bonk
	path := "/var/bonk"
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			fmt.Printf("error> %s\n", err)
		}
	}
	path = "/etc/bonk"
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			fmt.Printf("error> %s\n", err)
		}
	}

}

func main() {
<<<<<<< HEAD
	user, err := user.Current()
=======
	// userToNotKill := flag.String("user", "sysadmin", "the user to not kill with bonk")
	// configPath := flag.String("cf", "/etc/bonk/bonk.yaml", "the kill switch file of sorts")
	// logPath := flag.String("out", "bonk.log", "the log file to write to")
	loadTheRules := flag.Bool("l", true, "whether to embed the files (true or false)")
	rotateLogs := flag.Bool("r", false, "rotate logs (true or false)")
	safeUser := flag.String("u", "sysadmin", "the user to *NOT* kill")
	extremeMode := flag.Bool("e", false, "EXTREME MODE (true or false)")

	flag.Parse()

	if *loadTheRules {
		embedOurRules(RULESPATH)
		fmt.Println("[*] Embedded our rules")
		runCMD("augenrules --load", "failed to add rules")
		fmt.Println("[*] reloaded the rules")
		// clearLogs(LOGSPATH)
		runCMD("pkill -HUP auditd", "failed to restart auditd")
		fmt.Println("[*] restarted the service")

	}

	if *rotateLogs {
		runCMD("service auditd rotate", "failed to rotate logs")
		clearLogs(LOGSPATH)
		fmt.Println("[*] Cleared logs")
	}

	t, err := tail.TailFile(
		LOGSPATH, tail.Config{Follow: true, ReOpen: true})
>>>>>>> master
	if err != nil {
		log.Fatal(err)
	}

	if user.Username != "root" {
		log.Fatal("not root!")
	}

<<<<<<< HEAD
	fs.Parse(os.Args[1:])
	// color magic
	if !*colorEnabled {
		color.NoColor = true
	}

	// load configuration file
	if *configPath == "" {
		cf.Load(CONFIGPATH)
	} else {
		dumpConfig()
		cf.Load(*configPath)
	}
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
	} else if *mode == "bonk" || *mode == "honk" {
		return receive(client)
	} else {
		flag.PrintDefaults()
		return fmt.Errorf("please specify which mode to use")
	}

}

// command to load our rules
func load(r *libaudit.AuditClient) error {

	data, err := res.Open("embed/good.rules")
	if err != nil {
		return err
	}
	defer data.Close()

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

	return nil
}

func dumpConfig() error {
	data, err := res.Open("embed/config.json")
	if err != nil {
		return err
	}
	defer data.Close()

	// if config.json does not exist yet we can change that
	if _, err := os.Stat(CONFIGPATH); errors.Is(err, os.ErrNotExist) {
		output, err := os.OpenFile(CONFIGPATH, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
		if err != nil {
			return err
		}
		defer output.Close()

		_, err = io.Copy(output, data)
		if err != nil {
			return err
		}

		return nil

	}

	// otherwise there is something already there we should not override
	return nil

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
			if *mode == "bonk" {
				syscall.Kill(a.Pid, syscall.SIGKILL)
			}
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
				CoolLogger.Println(outMessage)
				if *verbose {
					fmt.Println(outMessage)
				}
			}
			return outMessage, nil
		} else { // otherwise the user is allowed
			outMessage = fmt.Sprintf("[%s] USER:%s\t;KEY %s\t; CMD: %s;\tCMD_F: %s;\t", color.HiMagentaString("COOL"),
				color.HiMagentaString(a.AuidHumanReadable), color.HiMagentaString(a.Key),
				color.HiMagentaString(a.Exe), color.HiMagentaString(a.Proctile),
			)

			if prev != outMessage {
				CoolLogger.Print(outMessage)
				if *verbose {
					fmt.Println(outMessage)
				}
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
					CoolLogger.Print(outMessage)
					if *verbose {
						fmt.Println(outMessage)
					}

				}
				return outMessage, nil

=======
	var bonkableOffenses = []string{}
	if *extremeMode {
		bonkableOffenses = []string{
			"unauthedfileaccess", "perm_mod", "etcpasswd", "etcgroup", "opasswd", "group_modification", "user_modification", "pam", "specialfiles", "cron", // modify users, touch cron or pam
			"sshd", "systemd", // touch systemd or ssh config files bonk
			"power",                                           // do not turn off our computers
			"priv_esc",                                        // su, sudo, sudoers, sudoers.d
			"susp_activity",                                   // wget, curl, base64, nc, netcat, ssh*, scp*, sftp*, ftp*, socat, wireshark, tshark, rawshark, rdesktop, nmap
			"sbin_susp",                                       // iptables, ip6tables, ifconfig*, arptables*,tcpdump, ufw*...
			"shell_profiles",                                  // modifying any of these: /etc/profile.d/ /etc/profile /etc/shells  /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/fish/ /etc/zsh/
			"software_mgmt",                                   // apt -> dnf -> yum -> dpkg -> snap -> pip3* , all killed
			"data_injection", "register_injection", "tracing"} // if they try to get cute and inject via ptrace we will know

		// The one's with the stars will probably be removed

		// "recon",                                           // whoami*, id*, hostname*, uname*, issue*, hostname*
		// recon broke ssh because of the ssh banner
	} else {
		bonkableOffenses = []string{
			"sudo", "data_injection", "register_injection", "tracing"}
	}

	var outMessage string
	var outMessagePrev string
	var a AuditMessage
	var prevID string
	var offensive bool
	// Print the text of each received line
	for line := range t.Lines {
		a.InitAuditMessage(line.Text)
		// fmt.Println(line.Text)
		if prevID == "" {
			prevID = a.AuditID
		}

		for _, offense := range bonkableOffenses {
			if a.Key == offense {
				offensive = true
				name, err := user.Lookup(*safeUser)
				if err != nil {
					log.Fatal(err)
				}

				if a.Auid != name.Uid && a.AuidHumanReadable != "root" && a.AuidHumanReadable != "unset" {
					commandBuilder := fmt.Sprintf("kill -9 %s", a.Pid)
					runCMD(commandBuilder, "failed to kill a pid")
					outMessage = fmt.Sprintf("[%s] CMD: %s;\tCMD_F: %s;\tUSER:%s\t;KEY %s\t;", color.RedString("BONK"),
						color.RedString(a.Exe), color.RedString(a.Proctile),
						color.RedString(a.AuidHumanReadable), color.RedString(a.Key))
					if outMessage != outMessagePrev {
						log.Print(outMessage)
					}
				}

				if a.Auid != name.Uid && a.Uid == "root" {
					outMessage = fmt.Sprintf("[%s] CMD: %s;\tCMD_F: %s;\tUSER:%s\t;KEY %s\t;", color.HiRedString("CRIT"),
						color.HiRedString(a.Exe), color.HiRedString(a.Proctile),
						color.HiRedString(a.AuidHumanReadable), color.HiRedString(a.Key))
					if outMessage != outMessagePrev {
						log.Print(outMessage)
					}
				}
				// else {
				// log.Printf("[%s] CMD: %s;\tCMD_F: %s;\tUSER:%s\t;KEY %s\t;", color.CyanString("FALSE"),
				// 	color.CyanString(a.Exe), color.CyanString(a.ProctileHumanreadable),
				// 	color.CyanString(a.AuidHumanReadable), color.CyanString(a.Key))
				// }

>>>>>>> master
			}
		}

		if !offensive && a.Key != "" {

			outMessage = fmt.Sprintf("[%s] CMD: %s;\tCMD_F: %s;\tUSER:%s\t;KEY %s\t;", color.BlueString("INFO"),
				color.BlueString(a.Exe), color.BlueString(a.Proctile),
				color.BlueString(a.AuidHumanReadable), color.BlueString(a.Key))

			if outMessage != outMessagePrev {
				log.Print(outMessage)
			}
		}
		offensive = false

		outMessagePrev = outMessage

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
			fmt.Println(fmt.Errorf("receive failed: %w", err))
		}

		// Messages from 1300-2999 are valid audit messages.
		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}

		// always save the raw audit log (for future investigation, of course
		RawLogger.Printf("type=%v msg=%v\n", rawEvent.Type, string(rawEvent.Data))

		// THIS IS THE BONK LOGIC
		if a.IsNewAuditID(string(rawEvent.Data)) {
			// so this is a new audit message
			// bonk the cumulative message
			if *mode == "bonk" || *mode == "honk" {
				prevMessage, _ = bonkProc(a, prevMessage)
			}
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
