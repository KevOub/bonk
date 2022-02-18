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
	"strings"

	"github.com/elastic/go-libaudit/rule"
	"github.com/elastic/go-libaudit/rule/flags"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
)

var (
	fs          = flag.NewFlagSet("audit", flag.ExitOnError)
	diag        = fs.String("diag", "logs", "dump raw information from kernel to file")
	mode        = fs.String("mode", "load", "[load/bonk] choose between\n>'load' (load rules)\n>'mode' (bonk processes) ")
	rate        = fs.Uint("rate", 0, "rate limit in kernel (default 0, no rate limit)")
	backlog     = fs.Uint("backlog", 8192, "backlog limit")
	immutable   = fs.Bool("immutable", false, "make kernel audit settings immutable (requires reboot to undo)")
	receiveOnly = fs.Bool("ro", false, "receive only using multicast, requires kernel 3.16+")
	//go:embed good.rules
	res embed.FS
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
	fmt.Println(r.GetRules())
	return nil
}

// watch output
func receive(r *libaudit.AuditClient) error {

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

		test, _ := auparse.Parse(rawEvent.Type, string(rawEvent.Data))
		fmt.Printf("record>\n%s\n", test.RawData)

		// a.InitAuditMessage(string(rawEvent.Data))
		// fmt.Printf("---\n%s\n---", a.Auid)
	}
}
