package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/elastic/go-libaudit/rule"
	"github.com/elastic/go-libaudit/rule/flags"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
)

var (
	fs          = flag.NewFlagSet("audit", flag.ExitOnError)
	diag        = fs.String("diag", "logs", "dump raw information from kernel to file")
	rate        = fs.Uint("rate", 0, "rate limit in kernel (default 0, no rate limit)")
	backlog     = fs.Uint("backlog", 8192, "backlog limit")
	immutable   = fs.Bool("immutable", false, "make kernel audit settings immutable (requires reboot to undo)")
	receiveOnly = fs.Bool("ro", false, "receive only using multicast, requires kernel 3.16+")
)

// // go:embed 43-module-load.rules
// var embededRules embed.FS

func main() {
	fs.Parse(os.Args[1:])

	if err := read(); err != nil {
		log.Fatalf("error: %v", err)
	}
}

const (
	// RULESPATH = "/etc/audit/rules.d/audit.rules"
	RULESPATH = "/etc/audit/rules.d/audit.rules"
	LOGSPATH  = "/var/log/bonk/bonk.log"
)

// embedOurRules
// func embedOurRules() {
// 	// os.O_TRUNC empties the file on opening
// 	// currentRules, err := os.OpenFile(RULESPATH, os.O_TRUNC, 0777)
// 	currentRules, err := os.OpenFile(RULESPATH, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_TRUNC, 0777)
// 	if err != nil {
// 		log.Fatalf("Failed to open operating system rules.\n%s", err)
// 	}
// 	defer currentRules.Close()

// 	_, err = currentRules.Write(embeddedRules)
// 	if err != nil {
// 		log.Fatalf("Failed to open operating system rules.\n%s", err)
// 	}
// }

// func runCMD(command, flavortext string) {
// 	byteCommand := strings.Split(command, " ") // splits into bytes seperated by spaces
// 	_, err := exec.Command(byteCommand[0], byteCommand[1:]...).Output()
// 	if err != nil {
// 		if _, ok := err.(*exec.ExitError); !ok {
// 			log.Fatalf("%s\n%s", flavortext, err)
// 		} else {
// 			fmt.Print(err)
// 		}
// 	}
// }

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

		// err = client.SetFailure(libaudit.SilentOnFailure, libaudit.NoWait)
		// if err != nil {
		// 	return fmt.Errorf("RAAA, %w", err)
		// }

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

		if status.Enabled != 2 {
			log.Printf("setting kernel settings as immutable")
			if err = client.SetImmutable(libaudit.NoWait); err != nil {
				return fmt.Errorf("failed to set kernel as immutable: %w", err)
			}
		}

		log.Printf("sending message to kernel registering our PID (%v) as the audit daemon", os.Getpid())
		if err = client.SetPID(libaudit.NoWait); err != nil {
			return fmt.Errorf("failed to set audit PID: %w", err)
		}

		rule2add := `-a never,exit -F arch=x86_64 -S adjtimex -F auid=unset -F uid=20 -F subj_type=chronyd_t1`

		r, err := flags.Parse(rule2add)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(client.GetStatus())

		// convert
		actualBytes, err := rule.Build(r)
		if err != nil {
			log.Fatal("rule:", rule2add, "error:", err)
		}

		if rules, err := client.GetRules(); err != nil {
			return fmt.Errorf("failed to add rule:\n %w", err)
		} else {
			fmt.Println(rules)
		}

		if err = client.AddRule([]byte(actualBytes)); err != nil {
			return fmt.Errorf("failed to add rule:\n %w", err)
		}
	}

	// logic to embed our rules
	// data, err := embededRules.Open("43-module-load.rules")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// data, err := os.Open("good.rules")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// client.DeleteRules() // funny stuff. nuke rules for sanity

	// scanner := bufio.NewScanner(data)
	// var test string
	// var read_line []byte
	// for scanner.Scan() {
	// 	test = scanner.Text()
	// 	read_line = []byte(strings.TrimSuffix(test, "\n"))
	// 	break
	// }
	// err = client.AddRule(read_line)

	// for scanner.Scan() {
	// 	err := client.AddRule(scanner.Bytes())

	// }

	// test, err := client.GetRules()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println(test)

	return receive(client)
}

func receive(r *libaudit.AuditClient) error {
	// var a AuditMessageBonk
	// err := r.AddRule([]byte(`-a never,exit -F arch=b64 -S adjtimex -F auid=unset -F uid=20 -F subj_type=chronyd_t`))
	// if err != nil {
	// 	log.Fatal(err)
	// }

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
		fmt.Printf("type=%v msg=%v\n", rawEvent.Type, string(rawEvent.Data))
		// a.InitAuditMessage(string(rawEvent.Data))
		// fmt.Printf("---\n%s\n---", a.Auid)
	}
}
