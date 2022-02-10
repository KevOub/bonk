package main

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
)

var (
	// auditIDRule = regexp.MustCompile("(:)(.*?)())")
	msgRule = regexp.MustCompile(`audit\((.*?)\)`)
	// syscall     = regexp.MustCompile("syscall=[0-9]{0,3}")

	terminalRule = regexp.MustCompile(`terminal=([\w\\/]+)`)
	ttyRule      = regexp.MustCompile(`tty=([\w\\/]+)`)
	exeRule      = regexp.MustCompile(`exe="(.*?)"`)
	keyRule      = regexp.MustCompile(`key="(.*?)"`)
	pidRule      = regexp.MustCompile(`pid=([\d]+)`)
	ppidRule     = regexp.MustCompile(`ppid=([\d]+)`)
	nameRule     = regexp.MustCompile(`name=\"(.*?)\"`)
	auidRule     = regexp.MustCompile(`auid=([\d].?)+`)
	proctileRule = regexp.MustCompile(`proctitle=(([\w].?)+)`)
)

type AuditMessage struct {
	// msg=audit(1364481363.243:24287):
	AuditIDRaw string
	AuditID    string
	Timestamp  string

	// syscall=2
	Syscall int
	// success=no
	Success bool

	// terminal=/dev/pts/0
	Terminal string
	// tty=pts0
	Tty string
	// exe="/bin/cat"
	Exe string
	// key="sshd_config"
	Key string

	// should be self explanatory
	Pid               string
	PPid              string
	Auid              string
	AuidHumanReadable string

	// name="/home/kevin"
	Name string

	// proctile=636174002F6574632F7373682F737368645F636F6E666967
	Proctile              string
	ProctileHumanreadable string

	// Finished is the flag to say that it is done processing
	// Extras
	Finished bool
}

func (a *AuditMessage) InitAuditMessage(line string) {
	a.AuditIDRaw = ParseAuditRuleRegex(msgRule, line, "")

	if a.AuditIDRaw != "" && len(a.AuditIDRaw) > 25 {
		a.Timestamp = a.AuditIDRaw[6:20]
		a.AuditID = a.AuditIDRaw[21:26]
	} else {
		return
	}
	// fmt.Printf("%s\t%s\n", a.Timestamp, a.AuditID)

	a.Terminal = ParseAuditRuleRegex(terminalRule, line, "terminal=")
	a.Tty = ParseAuditRuleRegex(ttyRule, line, "tty=")
	a.Exe = ParseAuditRuleRegex(exeRule, line, "exe=")
	a.Key = ParseAuditRuleRegex(keyRule, line, "key=")
	a.Pid = ParseAuditRuleRegex(pidRule, line, "pid=")
	a.PPid = ParseAuditRuleRegex(ppidRule, line, "ppid=")

	a.Auid = ParseAuditRuleRegex(auidRule, line, "auid=")
	if a.Auid != "" {
		commandBuilder := fmt.Sprintf("id -un %s", a.Auid)

		byteCommand := strings.Split(commandBuilder, " ") // splits into bytes seperated by spaces
		bytes, err := exec.Command(byteCommand[0], byteCommand[1:]...).Output()
		if err != nil {
			if _, ok := err.(*exec.ExitError); !ok {
				log.Fatalf("%s\n%s", "failed to get username", err)
			} else {
				fmt.Print(err)
			}
		}
		a.AuidHumanReadable = string(bytes)

	}
	a.Name = ParseAuditRuleRegex(nameRule, line, "name=")
	a.Proctile = ParseAuditRuleRegex(proctileRule, line, "proctitle=")
	a.ProctileHumanreadable = string(a.Proctile)

}

func ParseAuditRuleRegex(rules *regexp.Regexp, msg string, remove string) string {
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
	// trim first n characters just to have what is longer than the value
	output := string(value[sizeOfRemove:])

	// remove quotes
	if output[0] == '"' {
		outputWithoutQuotes := strings.Trim(output, "\"")
		return outputWithoutQuotes
	}

	return output

}
