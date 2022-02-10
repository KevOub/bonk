package main

import (
	"log"
	"regexp"
	"strings"
)

var (
	// auditIDRule = regexp.MustCompile("(:)(.*?)())")
	msgRule = regexp.MustCompile("msg=audit((.*?))")
	// syscall     = regexp.MustCompile("syscall=[0-9]{0,3}")

	terminalRule = regexp.MustCompile(`terminal=([\w\/]+)`)
	ttyRule      = regexp.MustCompile(`tty=([\w/]+)`)
	exeRule      = regexp.MustCompile(`exe="(.*?)"`)
	keyRule      = regexp.MustCompile(`key="(.*?)"`)
	pidRule      = regexp.MustCompile(`pid=([\d]+)`)
	ppidRule     = regexp.MustCompile(`ppid=([\d]+)`)
	nameRule     = regexp.MustCompile("name=\"(.*?)\"")
	auidRule     = regexp.MustCompile("AUID=\"(.*?)\"")
)

// type AuditMessage struct {
// 	// msg=audit(1364481363.243:24287):
// 	AuditIDRaw string
// 	AuditID    string
// 	Timestamp  string

// 	// syscall=2
// 	Syscall int
// 	// success=no
// 	Success bool

// 	// terminal=/dev/pts/0
// 	Terminal string
// 	// tty=pts0
// 	Tty string
// 	// exe="/bin/cat"
// 	Exe string
// 	// key="sshd_config"
// 	Key string

// 	// should be self explanatory
// 	Pid  string
// 	PPid string
// 	Auid string

// 	// name="/home/kevin"
// 	Name string

// 	// proctile=636174002F6574632F7373682F737368645F636F6E666967
// 	Proctile              string
// 	ProctileHumanreadable string

// 	// Finished is the flag to say that it is done processing
// 	// Extras
// 	Finished bool
// }

// func (a *AuditMessage) InitAuditMessage(line string) {
// 	// a.AuditIDRaw = ParseAuditRuleRegex(msgRule, line, "msg")

// }

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
