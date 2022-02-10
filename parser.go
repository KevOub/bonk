package main

import (
	"log"
	"regexp"
	"strings"
)

var (
	terminalRule = regexp.MustCompile(`terminal=([\w\/]+)`)
	ttyRule      = regexp.MustCompile(`tty=([\w/]+)`)
	exeRule      = regexp.MustCompile(`exe="(.*?)"`)
	keyRule      = regexp.MustCompile(`key="(.*?)"`)
	pidRule      = regexp.MustCompile(`pid=([\d]+)`)
	ppidRule     = regexp.MustCompile(`ppid=([\d]+)`)
	msgRule      = regexp.MustCompile("msg=audit((.*?))")
	nameRule     = regexp.MustCompile("name=\"(.*?)\"")
	auidRule     = regexp.MustCompile("AUID=\"(.*?)\"")
)

type AuditMessages struct {
	Terminal string
	Tty      string
	Exe      string
	Key      string
	Pid      string
	PPid     string
	Msg      string
	name     string
	Auid     string
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
