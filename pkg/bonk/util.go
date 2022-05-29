package bonk

import (
	"bytes"
	"fmt"
	"sync"
	"syscall"

	"github.com/elastic/go-libaudit/rule"
	"github.com/elastic/go-libaudit/rule/flags"
	"github.com/elastic/go-libaudit/v2"
)

// RuleAlreadyAdded() takes the rule to add and the current rules and returns true if the rule is already added
func RuleAlreadyAdded(currentRule []byte, allRules [][]byte) bool {

	for _, rule := range allRules {
		if bytes.Equal(rule, currentRule) {
			return true
		}
	}

	return false

}

// RuleBuilder() wraps the steps to make the rule into the binary equivalent and returns the []byte val
func RuleBuilder(rule2add string, currRules [][]byte) ([]byte, error) {

	ru, err := flags.Parse(rule2add)
	if err != nil {
		return nil, err
	}

	// convert
	actualBytes, err := rule.Build(ru)
	if err != nil {
		return nil, err
	}

	return actualBytes, nil
}

// RuleAddWrapper() takes the string to add plus the client and handles the weird translation process to get the kernel to like it
func RuleAddWrapper(rule2add string, r *libaudit.AuditClient, currRules [][]byte) error {
	/*
		Could in theory make this faster by using goroutines but I do not want to find a race condition in the kernel
	*/

	ru, err := flags.Parse(rule2add)
	if err != nil {
		return err
	}

	// convert
	actualBytes, err := rule.Build(ru)
	if err != nil {
		return err
	}

	if RuleAlreadyAdded([]byte(actualBytes), currRules) {
		fmt.Print("Already added!\n")

	}

	r.WaitForPendingACKs()

	if err = r.AddRule([]byte(actualBytes)); err != nil {
		return fmt.Errorf("failed to add rule:\n %w", err)
	}

	return nil
}

// BonkCheckVerbose is a verbose multi-step stager that goes through various methods
// to determine whether or not the audit message warrants the PID to be bonked
func BonkCheckVerbose(a AuditMessageBonk, config Config) {

	bonkableChann := make(chan map[string]bool)
	bonkBadProcesses := config.Operation == BONK || config.Operation == LOCKANDLOAD // variable to represent whether or not to kill proccess
	killProcess := false
	var wg sync.WaitGroup

	// first, check if user is allowed to do what the user needs to do
	if config.AllowedUser(a.AuidHumanReadable) {
		return
	}

	// second, check if user is in an allowed IP address TODO
	// if config.AllowedIP(){}

	// third, check the lists of offenses. For now it is just the DenyList and the rules from auditd itself which are bad
	// in the future YARA rule integration can be added here and it should seamlessly fit in
	// Another option is to have afunction which checks hashes against the audit messages' PID's ioctl number

	if config.DenyListMode {
		wg.Add(1)
		go func() {
			result := map[string]bool{"ip-deny": false}
			bonkableChann <- result
		}()
	}

	if config.Operation == BONK || config.Operation == HONK || config.Operation == LOCKANDLOAD {
		wg.Add(1)
		go func() {
			result := map[string]bool{"bonkable-pid": false}
			if config.IsBonkable(a.Key) {
				result["bonkable-pid"] = true
			}
			bonkableChann <- result
		}()
	}

	// collects all the willy nilly channels
	go func() {
		// defer wg.Done() <- Never gets called since the 100 `Done()` calls are made above, resulting in the `Wait()` to continue on before this is executed
		// go through the offenses possible [ip-allow,ip-deny, and bonkable-pid] to determine if the process should be killed
		for val := range bonkableChann {
			for offense, violated := range val {
				if violated && bonkBadProcesses {
					// boom killed
					killProcess = true
					// TODO add logging here to explain which part got bonked
					fmt.Printf("[!] The process with PID %d was seen in violation of %s\n", a.Pid, offense)
				}

			}
			if killProcess {
				syscall.Kill(a.Pid, syscall.SIGKILL)
			}

			wg.Done() // ** move the `Done()` call here
		}
	}()

	wg.Wait()
	fmt.Printf("%+v\n", a)

}
