package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/nxadm/tail"
)

var (
	terminalRule = regexp.MustCompile(`terminal=([\w/]+)`)
	ttyRule      = regexp.MustCompile(`tty=([\w/]+)`)
	exeRule      = regexp.MustCompile(`exe="(.*?)"`)
	keyRule      = regexp.MustCompile(`key="(.*?)"`)
	pidRule      = regexp.MustCompile(`pid=([\d]+)`)
	msgRule      = regexp.MustCompile("msg=audit((.*?))")
	nameRule     = regexp.MustCompile("name=\"(.*?)\"")
)

//go:embed audit.rules
var embeddedRules []byte

func parseAuditRuleRegex(rules *regexp.Regexp, msg string, remove string) string {
	// apply regex magic. Maybe could be better
	value := rules.Find([]byte(msg))

	// if it zero nothing found
	if len(value) == 0 {
		return ""
	}
	sizeOfRemove := len(remove)
	output := string(value[sizeOfRemove:])

	if output[0] == '"' {
		outputWithoutQuotes := strings.Trim(output, "\"")
		return outputWithoutQuotes
	}
	return output

}

// TODO future problem
func embedOurRules() {

	currentRules, err := os.Open("/etc/audit/rules.d/audit.rules")
	if err != nil {
		log.Fatalf("Failed to open operating system rules.\n%s", err)
	}
	defer currentRules.Close()

	currentRules.Write(embeddedRules)
	// err = exec.Command("auditctl /etc/audit/rules.d/audit.rules").Run()
	// if err != nil {
	// 	log.Fatal(err)
	// }

}

func init() {
	// embedOurRules()
}

func main() {
	t, err := tail.TailFile(
		"/var/log/audit/audit.log", tail.Config{Follow: true, ReOpen: true})
	if err != nil {
		panic(err)
	}
	// var exeName

	// Print the text of each received line

	for line := range t.Lines {

		key := parseAuditRuleRegex(keyRule, string(line.Text), "key=")

		if key == "specialfiles" || key == "cron" || key == "priv_esc" || key == "etcpasswd" {

			pid := parseAuditRuleRegex(pidRule, string(line.Text), "pid=")

			commandRan := parseAuditRuleRegex(exeRule, string(line.Text), "exe=")

			ttyName := parseAuditRuleRegex(ttyRule, string(line.Text), "tty=")

			fmt.Printf("key : %s\n\t TERMINAL:\t%s\tpid:\t%s\tterminal:\t%s", key, ttyName, pid, commandRan)
			fmt.Print("---\n")

			// so that I do not kill *all* processes
			if ttyName == "pts2" || key == "etcpasswd" || key == "priv_esc" {
				_, err := exec.Command("kill", "-9", pid).Output()
				// whereToWrite := fmt.Sprintf("/proc/%s/fd/0", pid)
				// _, err := exec.Command("echo", "bonk", ">", whereToWrite).Output()
				if err != nil {
					if _, ok := err.(*exec.ExitError); !ok {
						fmt.Println("Failed to do the deed")
					}
				}

			}

		}

		// if string(Key) == "high" {
		// 	// commandBuilder := fmt.Sprintf("kill -9 %s", PID)

		// commandBuilder := fmt.Sprintf(" head -n 1000000 /dev/urandom | base64 >  %s", terminalSession)
		// commandBuilder := fmt.Sprintf("ps -p %s -o format", pid)
		// cmd, _ := exec.Command(commandBuilder).Output()
		// cmd.Run()
		// fmt.Println(cmd)
		// 	fmt.Print("RUNNING")

		// }

		// fmt.Println(terminalSession)
		// fmt.Println(line.Text)
	}

}
