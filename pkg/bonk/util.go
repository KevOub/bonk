package bonk

import (
	"bytes"
	"fmt"
	"strconv"
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

// BonkEnforcer is a verbose multi-step stager that goes through various methods
// to determine whether or not the audit message warrants the PID to be bonked
func BonkEnforcer(a Parser, config Config) {

	// bonkableChann := make(chan map[string]bool)
	killProcess := false
	violations := []string{}

	// first, check if user is allowed to do what the user needs to do
	// fmt.Printf("auid=%s\n", a.Get("auid"))
	// fmt.Printf("AUID=%s\n", a.Get("AUID"))
	// if config.AllowedUser(a.Get("auid")) {
	// return
	// }
	// fmt.Println(config.AllowedUser(a.Get("auid")))

	pidSTR := a.Get("pid")
	fmt.Println(pidSTR)
	// if pidSTR == "" {
	// return
	// }
	pid, err := strconv.Atoi(a.Get("pid"))
	if err != nil {
		fmt.Printf("error converting PID to int: %v\n", err)
	}

	if config.AllowListMode {
		data, _ := getIPfromPID(pid)
		for ip, _ := range data {
			if config.AllowedIP(ip) {
				if config.Verbose {
					fmt.Printf("IP %s is in the allow list\n", ip)
				}
				killProcess = false
				// if we are in the IP allow list and see a permitted IP, return immediately
				// no harm to this IP
				return
			}

		}
	}

	if config.DenyListMode {
		data, _ := getIPfromPID(pid)
		for ip, _ := range data {
			if config.BannedIP(ip) {
				if config.Verbose {
					fmt.Printf("IP %s is in the deny list\n", ip)
				}
				// if we are in the IP deny list and see a banned IP, label the process as bad
				violations = append(violations, fmt.Sprintf("IP (%s) in deny list", ip))
				killProcess = true
			}

		}
	}

	if config.Operation == BONK || config.Operation == LOCKANDLOAD || config.Operation == HONK {
		keyval := a.Get("key")
		// s = s[1 : len(s)-1]
		keyval = keyval[1 : len(keyval)-1]

		if config.IsBonkable(keyval) {
			if config.Verbose {
				fmt.Printf("%s is in the bonk list\n", a.Get("key"))
			}
			violations = append(violations, fmt.Sprintf("%s in bonk list", a.Get("key")))
			killProcess = true
		}
	}

	fmt.Printf("violations: %v\n", violations)
	// Finally, nuke process from orbit
	if killProcess {

		fmt.Printf("The process %d has commited these crimes\n", pid)
		for _, v := range violations {
			fmt.Printf("\t>%s\n", v) // listing violations
		}

		if config.Operation == HONK {
			fmt.Printf("[The process %d would be bonked if not mode honk]\n", pid)
			return
		}

		err := syscall.Kill(pid, syscall.SIGKILL)
		if err != nil {
			fmt.Printf("error killing process: %v\n", err)
		}
	}

}
