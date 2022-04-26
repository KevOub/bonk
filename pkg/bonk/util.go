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

// import (
// 	"errors"
// 	"fmt"
// 	"io"
// 	"os"
// 	"syscall"

// 	"github.com/elastic/go-libaudit/rule"
// 	"github.com/elastic/go-libaudit/rule/flags"
// 	"github.com/elastic/go-libaudit/v2"
// 	"github.com/fatih/color"
// )

// // dumConfig() takes the embedded json file from the binary to the location /etc/bonk/config.json
// func dumpConfig() error {
// 	data, err := res.Open("embed/config.json")
// 	if err != nil {
// 		return err
// 	}
// 	defer data.Close()

// 	// if config.json does not exist yet we can change that
// 	if _, err := os.Stat(CONFIGPATH); errors.Is(err, os.ErrNotExist) {
// 		output, err := os.OpenFile(CONFIGPATH, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
// 		if err != nil {
// 			return err
// 		}
// 		defer output.Close()

// 		_, err = io.Copy(output, data)
// 		if err != nil {
// 			return err
// 		}

// 		return nil

// 	}

// 	// otherwise there is something already there we should not override
// 	return nil

// }

// // handleIP() takes a pid and the event string to log which IP's are naughty
// func handleIP(pid int, event string) {
// 	// wacky code which reads /proc/*PID*/net/tcp for established ip addresses
// 	establishedIPAdresses, err := getIPfromPID(pid)
// 	if err == nil {
// 		for key := range establishedIPAdresses {

// 			if _, exists := IPAddresses[key]; !exists {
// 				IPAddresses[key] = 0
// 			} else {
// 				IPAddresses[key] += 1
// 				if IPAddresses[key] > *BonksBeforeWarn {
// 					OutPutMessage := fmt.Sprintf("[WARN] THE IP ADDRESS %s IS BEING SUSPICIOUS", color.HiYellowString(key))
// 					fmt.Println(OutPutMessage)
// 					IPAddresses[key] = 0 // reset the warns back to 0
// 				}

// 			}
// 			saveIP(key, event)
// 		}
// 	}
// }

// // saveIP is POC code to show saving IP address
// func saveIP(ip string, event string) error {
// 	output, err := os.OpenFile(IPADDRESSES, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
// 	if err != nil {
// 		return err
// 	}
// 	defer output.Close()

// 	output.WriteString(event + "IP=" + ip + "\n---\n")
// 	if err != nil {
// 		return err
// 	}

// 	return nil

// }

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

	// r.WaitForPendingACKs()
	// test, err := r.GetRules()
	// if err != nil {
	// fmt.Println(err)
	// }

	if RuleAlreadyAdded([]byte(actualBytes), currRules) {
		fmt.Print("Already added!\n")

	}

	r.WaitForPendingACKs()

	if err = r.AddRule([]byte(actualBytes)); err != nil {
		return fmt.Errorf("failed to add rule:\n %w", err)
	}

	return nil
}

// BonkCheck is a verbose multi-step stager that goes through various methods
// to determine whether or not the audit message warrants the PID to be bonked
func BonkCheck(a AuditMessageBonk, config Config) {

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

// // BonkProc() takes each audit message and determines whether they should be bonked
// func BonkProc(a AuditMessageBonk, prev, mode string) (string, error) {

// 	/* OPTIONS:
// 	1) HONK: nothing gets killed
// 	2) BONK: everything gets killed
// 	3) BONk+BonkByIP-D : kill all suspicious process from IP address in deny list
// 	3) BONk+BonkByIP-A : do not kill IP in allowed IP addresses
// 	*/

// 	// fmt.Printf("%v", IPAddresses)

// 	var outMessage string

// 	// try to bonk the process by IP
// 	// if (mode == "bonk" || mode == "honk") && BonkByIPDeny {
// 	// 	// check to see if the process has been bonked
// 	// 	if status := bonkIP(a); status {
// 	// 		outMessage = fmt.Sprintf("[%s] USER:%s\t;KEY %s\t; CMD: %s;\tCMD_F: %s;\t", color.RedString("DENY-IP"),
// 	// 			color.RedString(a.AuidHumanReadable), color.RedString(a.Key),
// 	// 			color.RedString(a.Exe), color.RedString(a.Proctile),
// 	// 		)
// 	// 		if prev != outMessage {
// 	// 			CoolLogger.Println(outMessage)
// 	// 			if *verbose {
// 	// 				fmt.Println(outMessage)
// 	// 			}
// 	// 		}
// 	// 		handleIP(a.Pid, outMessage)
// 	// 		return outMessage, nil
// 	// 	}
// 	// }

// 	// if the offense is bonkable
// 	if cf.IsBonkable(a.Key) {

// 		// and the user is *not* allowed
// 		if !cf.AllowedUser(a.AuidHumanReadable) {

// 			// do not bonk some IP addresses if it is in the approvad IP address list
// 			if *BonkByIPAllow {
// 				IPs, _ := getIPfromPID(a.Pid)
// 				for ip := range IPs {
// 					if cf.AllowedIP(ip) {
// 						// output message
// 						outMessage = fmt.Sprintf("[%s:%s] USER:%s\t;KEY %s\t; CMD: %s;\tCMD_F: %s;\t", color.GreenString("ALLOW-IP"), color.GreenString(ip),
// 							color.GreenString(a.AuidHumanReadable), color.GreenString(a.Key),
// 							color.GreenString(a.Exe), color.GreenString(a.Proctile),
// 						)

// 						if prev != outMessage {
// 							CoolLogger.Print(outMessage)
// 							if *verbose {
// 								fmt.Println(outMessage)
// 							}
// 						}
// 						return outMessage, nil
// 					}
// 				}
// 			}

// 			// otherwise, nuke the process
// 			if *mode == "bonk" { // bonk the process!

// 				syscall.Kill(a.Pid, syscall.SIGKILL)
// 			}

// 			outMessage = fmt.Sprintf("[%s] USER:%s\t;KEY %s\t; CMD: %s;\tCMD_F: %s;\t", color.RedString("BONK"),
// 				color.RedString(a.AuidHumanReadable), color.RedString(a.Key),
// 				color.RedString(a.Exe), color.RedString(a.Proctile),
// 			)
// 			if prev != outMessage {
// 				CoolLogger.Println(outMessage)
// 				if *verbose {
// 					fmt.Println(outMessage)
// 				}
// 			}
// 			handleIP(a.Pid, outMessage)
// 			return outMessage, nil
// 		} else { // otherwise the user is allowed
// 			outMessage = fmt.Sprintf("[%s] USER:%s\t;KEY %s\t; CMD: %s;\tCMD_F: %s;\t", color.HiMagentaString("COOL"),
// 				color.HiMagentaString(a.AuidHumanReadable), color.HiMagentaString(a.Key),
// 				color.HiMagentaString(a.Exe), color.HiMagentaString(a.Proctile),
// 			)

// 			if prev != outMessage {
// 				CoolLogger.Print(outMessage)
// 				if *verbose {
// 					fmt.Println(outMessage)
// 				}
// 			}
// 			handleIP(a.Pid, outMessage)
// 			return outMessage, nil
// 		}

// 	} else {
// 		// only log notable events
// 		if a.Key != "" {
// 			// then the message is not bonkable
// 			if *showInfo {
// 				outMessage = fmt.Sprintf("[%s] USER:%s\t;KEY %s\t; CMD: %s;\tCMD_F: %s;\t", color.BlueString("INFO"),
// 					color.BlueString(a.AuidHumanReadable), color.BlueString(a.Key),
// 					color.BlueString(a.Exe), color.BlueString(a.Proctile),
// 				)
// 				if outMessage != prev {
// 					CoolLogger.Print(outMessage)
// 					if *verbose {
// 						fmt.Println(outMessage)
// 					}

// 				}
// 				return outMessage, nil

// 			}
// 		}

// 	}
// 	return "", nil
// }

// // logic to kill processes from unknown sources :) (bonkip-d)
// func bonkIP(a AuditMessageBonk) bool {
// 	// If IP Deny
// 	if (*BonkByIPDeny) && (*mode == "bonk" || *mode == "honk") {
// 		processIPs, err := getIPfromPID(a.Pid)
// 		if err != nil && *verbose {
// 			fmt.Printf("error> %v\n", err)
// 			return false
// 		}
// 		for IP := range processIPs {

// 			if cf.BannedIP(IP) && *BonkByIPDeny {
// 				if *mode == "bonk" {
// 					syscall.Kill(a.Pid, syscall.SIGKILL)
// 					return true

// 				} else {
// 					fmt.Printf("[Warn] Bonk -deny- would have nuked this process %v\n", IP)
// 				}

// 			}
// 		}

// 	}
// 	return false
// }
