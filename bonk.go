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

//go:embed bonk.art
var bonkArt []byte

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
	// os.O_TRUNC empties the file on opening
	// currentRules, err := os.OpenFile(RULESPATH, os.O_TRUNC, 0777)
	currentRules, err := os.OpenFile(RULESPATH, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0777)
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

func clearLogs() {
	f, err := os.OpenFile(LOGSPATH, os.O_TRUNC, 0777)
	if err != nil {
		log.Fatalf("Failed to yeet the contents of %s:%v", LOGSPATH, err)
	}
	stat, err := f.Stat()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(stat.Size())
	f.Close()
}

func init() {
	// first copy logs because they might be important

	// TODO make this backup log
	// Copy(LOGSPATH, "/v")
	clearLogs()
	fmt.Println("[*] Cleared logs")

	embedOurRules()
	fmt.Println("[*] Embedded our rules")

	runCMD("augenrules --load", "failed to add rules")
	fmt.Println("[*] reloaded the rules")
	runCMD("service auditd rotate", "failed to rotate logs")
	runCMD("pkill -HUP auditd", "failed to add rules")
	// runCMD("service auditd start", "failed to restart audit")
	// runCMD("service start auditd", "failed to restart audit")
	fmt.Println("[*] restarted the service")
}

func main() {
	t, err := tail.TailFile(
		LOGSPATH, tail.Config{Follow: true, ReOpen: true})
	if err != nil {
		panic(err)
	}

	// extra line just to print bonk boi

	fmt.Println(string(bonkArt))

	// Print the text of each received line
	for line := range t.Lines {

		key := parseAuditRuleRegex(keyRule, string(line.Text), "key=")

		if key == "specialfiles" || key == "cron" || key == "priv_esc" || key == "etcpasswd" {

			pid := parseAuditRuleRegex(pidRule, string(line.Text), "pid=")

			commandRan := parseAuditRuleRegex(exeRule, string(line.Text), "exe=")

			ttyName := parseAuditRuleRegex(ttyRule, string(line.Text), "tty=")

			// terminalName := parseAuditRuleRegex(terminalRule, string(line.Text), "terminal=")

			// ppid := parseAuditRuleRegex(ppidRule, string(line.Text), "ppid=")

			fmt.Printf("key : %s\n\t TERMINAL:\t%s\tpid:\t%s\tterminal:\t%s", key, ttyName, pid, commandRan)
			fmt.Print("---\n")

			// so that I do not kill *all* processes
			if key == "etcpasswd" || key == "priv_esc" {
				fmt.Println("test")
				// newPTY := strings.Replace(ttyName, "s", "s/", 1)
				// fmt.Println(newPTY)

				// commandBuilder := fmt.Sprintf("wall -g 1000 \" Bonked this terminal! : %s \"", ttyName)
				// runCMD(commandBuilder, "failed to kill a pid")

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
