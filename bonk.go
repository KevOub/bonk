package main

import (
	"fmt"
	"regexp"

	"github.com/nxadm/tail"
)

var (
	terminalSessionRule = regexp.MustCompile(`terminal=([a-zA-Z\/0-9]+)`)
	exeRule             = regexp.MustCompile(`exe="(.*?)"`)
	keyRule             = regexp.MustCompile(`key="(.*?)"`)
	pidRule             = regexp.MustCompile(`pid=([\d]+)`)
)

func parseAuditRuleRegex(rules *regexp.Regexp, msg string, remove string) string {
	value := rules.Find([]byte(msg))
	if len(value) == 0 {
		// fmt.Println("Failed to find regex")
		return ""
	}
	sizeOfRemove := len(remove)
	return string(value[sizeOfRemove:])

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
		// terminalSession := terminalSessionRule.Find([]byte(line.Text))
		// PID := pidRule.Find([]byte(line.Text))
		// commandRan := exeRule.Find([]byte(line.Text))
		// Key := keyRule.Find(([]byte(line.Text)))
		// fmt.Printf("\nTERM=%s\tPID=%s\tCMD=%s\tKEY=%s\n", terminalSession, PID, commandRan, Key)

		key := parseAuditRuleRegex(keyRule, string(line.Text), "key=")

		if key == "specialfiles" || key == "unauthedfileaccess" || key == "priv_esc" {

			fmt.Printf("key = %s\n", key)
			fmt.Print("---\n")

			pid := parseAuditRuleRegex(pidRule, string(line.Text), "pid=")
			fmt.Printf("pid = %s\n", pid)

			commandRan := parseAuditRuleRegex(exeRule, string(line.Text), "exe=")
			fmt.Printf("cmd = %s\n", commandRan)

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
