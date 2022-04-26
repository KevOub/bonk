package bonk

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
)

var (
	fs          = flag.NewFlagSet("audit", flag.ExitOnError)
	diag        = fs.String("diag", "", "dump raw information from kernel to file")
	rate        = fs.Uint("rate", 0, "rate limit in kernel (default 0, no rate limit)")
	backlog     = fs.Uint("backlog", 8192, "backlog limit")
	immutable   = fs.Bool("immutable", false, "make kernel audit settings immutable (requires reboot to undo)")
	receiveOnly = fs.Bool("ro", false, "receive only using multicast, requires kernel 3.16+")
)

func StreamAudit(parser AuditMessageBonk, config Config, bonkfunc func(AuditMessageBonk, Config)) {

	if err := read(parser, config, bonkfunc); err != nil {
		log.Fatalf("error: %v", err)
	}

}

func read(parser AuditMessageBonk, config Config, bonkfunc func(AuditMessageBonk, Config)) error {
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

		// if status.Enabled != 2 && *immutable {
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

	// go straight to bonking
	if config.Operation == HONK || config.Operation == BONK {
		return receive(client, config, parser, bonkfunc)
	}

	// go to loading
	if config.Operation == LOAD {
		return load(config, client)
	}

	// lock and load is load then receive
	if config.Operation == LOCKANDLOAD {
		client.WaitForPendingACKs()
		err = load(config, client)

		// err := load(config, client)
		if err != nil {
			return err
		} else {
			return receive(client, config, parser, bonkfunc)
		}
	}

	return fmt.Errorf("ConfigOperation is not set")
}

// load() takes a copy of the config object and the client
// It then combines the embedded rules and the custom rules set out in the Config struct
func load(config Config, r *libaudit.AuditClient) error {
	// var wg sync.WaitGroup
	currRules, err := r.GetRules()
	if err != nil {
		return err
	}

	// code to combine the strings of the rules into one blob
	embedrules := strings.Split(string(config.EmbeddedRules), "\n")
	customrules := config.Rules
	var allrules []string
	if config.DontEmbedRules {
		allrules = customrules
	} else {
		allrules = append(embedrules, customrules...)
	}

	// map that has the rule on the left and the value of the byte on the right
	RuleByteEq := make(map[string][]byte)

	// go through the embedded rules seperated by new line
	for _, m := range allrules {

		// if the rule is not null and does not start with #
		if rule2add := m; !strings.HasPrefix(rule2add, "#") && rule2add != "" {
			value, err := RuleBuilder(rule2add, currRules)

			RuleByteEq[rule2add] = value
			if config.Verbose {
				if err != nil {
					fmt.Printf("error> %s\n", err)
				} else {
					fmt.Printf("> Found rule :%s\n", rule2add)

				}
			}

		}

	}

	// go through and add all rules
	start := time.Now()
	for key, val := range RuleByteEq {
		rule := val
		// err := RuleAddWrapper(rule, r, currRules)
		if !RuleAlreadyAdded(val, currRules) {
			r.AddRule(rule)
			r.WaitForPendingACKs()
			if config.Verbose {
				fmt.Printf("> Added rule :%s\n", key)
				if err != nil {
					fmt.Printf("error> %s\n", err)
				}
			}
		}

	}
	finished := time.Since(start)

	if config.Verbose {
		fmt.Println("Finished adding all the rules!")
		fmt.Printf("That took %s seconds...\n", finished)
	}

	return nil

}

// receive is the game loop essentially. It goes forever looking for new messages running bonkfunc when the AuditID does not match the previous
func receive(r *libaudit.AuditClient, config Config, parser AuditMessageBonk, bonkfunc func(AuditMessageBonk, Config)) error {
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

		// if the parser has a new AuditID start the bonk process
		if parser.IsNewAuditID(string(rawEvent.Data)) {
			// TODO add to config to set mode
			bonkfunc(parser, config)

			parser = AuditMessageBonk{}
			parser.InitAuditMessage(string(rawEvent.Data))

		} else {
			parser.InitAuditMessage(string(rawEvent.Data))
			err := parser.InitAuditMessage(string(rawEvent.Data))
			if err != nil {
				fmt.Print(err)
			}
		}
		// fmt.Printf("type=%v msg=%v\n", rawEvent.Type, string(rawEvent.Data))
	}
}
