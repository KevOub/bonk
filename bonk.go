package main

import (
	_ "embed"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/nxadm/tail"
)

const (
	RULESPATH = "/etc/audit/rules.d/audit.rules"
	LOGSPATH  = "/var/log/audit/audit.log"
)

var (
	terminalRule = regexp.MustCompile(`terminal=([\w/]+)`)
	ttyRule      = regexp.MustCompile(`tty=([\w/]+)`)
	exeRule      = regexp.MustCompile(`exe="(.*?)"`)
	keyRule      = regexp.MustCompile(`key="(.*?)"`)
	pidRule      = regexp.MustCompile(`pid=([\d]+)`)
	ppidRule     = regexp.MustCompile(`ppid=([\d]+)`)
	msgRule      = regexp.MustCompile("msg=audit((.*?))")
	nameRule     = regexp.MustCompile("name=\"(.*?)\"")
)

//go:embed good.rules
var embeddedRules []byte

// turns regex rule to human readable
func parseAuditRuleRegex(rules *regexp.Regexp, msg string, remove string) string {
	// apply regex magic. Maybe could be better
	value := rules.Find([]byte(msg))

	// if it zero nothing found
	if len(value) == 0 {
		return ""
	}
	sizeOfRemove := len(remove)

	if sizeOfRemove > len(value) {
		log.Fatalf("REMOVE=%s is too long for msg=%s\n", remove, msg)
	}
	output := string(value[sizeOfRemove:])

	if output[0] == '"' {
		outputWithoutQuotes := strings.Trim(output, "\"")
		return outputWithoutQuotes
	}
	return output

}

// Copy the src file to dst. Any existing file will be overwritten and will not
// copy file attributes.
func Copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

// TODO future problem
func embedOurRules() {

	currentRules, err := os.OpenFile(RULESPATH, os.O_TRUNC, 0777)
	if err != nil {
		log.Fatalf("Failed to open operating system rules.\n%s", err)
	}
	defer currentRules.Close()

	// err = currentRules.Truncate(0)
	// if err != nil {
	// 	log.Fatalf("Failed to empty file", err)
	// }

	currentRules.Write(embeddedRules)
	// err = exec.Command("auditctl /etc/audit/rules.d/audit.rules").Run()
	// if err != nil {
	// 	log.Fatal(err)
	// }

}

func runCMD(command, flavortext string) {
	byteCommand := strings.Split(command, " ")
	_, err := exec.Command(byteCommand[0], byteCommand[1:]...).Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			log.Fatalf("%s\n%s", flavortext, err)
		}
	}
}

func clearLogs() {
	// err := os.Truncate(LOGSPATH, 1)
	// if err != nil {
	// 	log.Fatalf("Failed to yeet the contents of %s:%v", LOGSPATH, err)
	// }
	f, err := os.OpenFile(LOGSPATH, os.O_TRUNC, 0777)
	if err != nil {
		log.Fatalf("Failed to yeet the contents of %s:%v", LOGSPATH, err)
	}
	f.Close()
}

func init() {
	// first copy logs because they might be important

	// TODO make this backup log
	// Copy(LOGSPATH, "/v")
	clearLogs()
	embedOurRules()
	runCMD("augenrules --load", "failed to add rules")
	runCMD("service start auditd", "failed to restart audit")

}

func main() {
	t, err := tail.TailFile(
		LOGSPATH, tail.Config{Follow: true, ReOpen: true})
	if err != nil {
		panic(err)
	}

	// Print the text of each received line
	for line := range t.Lines {

		key := parseAuditRuleRegex(keyRule, string(line.Text), "key=")

		if key == "specialfiles" || key == "cron" || key == "priv_esc" || key == "etcpasswd" {

			pid := parseAuditRuleRegex(pidRule, string(line.Text), "pid=")

			commandRan := parseAuditRuleRegex(exeRule, string(line.Text), "exe=")

			ttyName := parseAuditRuleRegex(ttyRule, string(line.Text), "tty=")

			// ppid := parseAuditRuleRegex(ppidRule, string(line.Text), "ppid=")

			fmt.Printf("key : %s\n\t TERMINAL:\t%s\tpid:\t%s\tterminal:\t%s", key, ttyName, pid, commandRan)
			fmt.Print("---\n")

			// so that I do not kill *all* processes
			if key == "etcpasswd" || key == "priv_esc" {
				newPTY := strings.Replace(ttyName, "s", "s/", 1)
				fmt.Println(newPTY)

				commandBuilder := fmt.Sprintf("kill -9 %s", pid)
				runCMD(commandBuilder, "failed to kill a pid")

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
