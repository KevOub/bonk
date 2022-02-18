package main

import (
	"log"
	"regexp"
	"strings"
)

var (
	// auditIDRule = regexp.MustCompile("(:)(.*?)())")
	msgRule = regexp.MustCompile(`audit\((.*?)\)`)
	// syscall     = regexp.MustCompile("syscall=[0-9]{0,3}")

	terminalRule  = regexp.MustCompile(`terminal=([\w\\/]+)`)
	ttyRule       = regexp.MustCompile(`tty=([\w\\/]+)`)
	exeRule       = regexp.MustCompile(`exe="(.*?)"`)
	keyRule       = regexp.MustCompile(`key="(.*?)"`)
	pidRule       = regexp.MustCompile(`pid=([\d]+)`)
	ppidRule      = regexp.MustCompile(`ppid=([\d]+)`)
	nameRule      = regexp.MustCompile(`name=\"(.*?)\"`)
	auidRule      = regexp.MustCompile(`auid=([\d].?)+`)
	auidRuleAlpha = regexp.MustCompile(`AUID="(.*?)"`)
	proctileRule  = regexp.MustCompile(`proctitle=(([\w].?)+)`)
	// Rules        = make(map[*regexp.Regexp]string)
)

// func init() {
// 	Rules[terminalRule] = "terminal="
// 	Rules[ttyRule] = "tty="
// 	Rules[exeRule] = "exe="
// 	Rules[keyRule] = "key="
// 	Rules[pidRule] = "pid="
// 	Rules[ppidRule] = "ppid="
// 	Rules[nameRule] = "name="
// 	Rules[auidRule] = "auid="
// 	Rules[proctileRule] = "proctitle="
// }

type AuditMessage struct {
	// msg=audit(1364481363.243:24287):
	AuditIDRaw string `json:"-"`
	AuditID    string `json:"auditID"`
	Timestamp  string `json:"timestamp"`

	// syscall=2 (not used)
	Syscall int `json:"Syscall"`
	// success=no
	Success bool `json:"success"`

	// terminal=/dev/pts/0 (not found often ???)
	Terminal string `json:"terminal"`
	// tty=pts0
	Tty string `json:"tty"`
	// exe="/bin/cat"
	Exe string `json:"exe"`
	// key="sshd_config"
	Key string `json:"key"`

	// should be self explanatory
	Pid               string `json:"pid"`
	PPid              string `json:"ppid"`
	Uid               string `json:"uid"`
	Auid              string `json:"auid"`
	AuidHumanReadable string `json:"auid-hr"` //human readable

	// name="/home/kevin"
	Name string `json:"name"`

	// proctile=636174002F6574632F7373682F737368645F636F6E666967
	Proctile              string `json:"proctitle"`
	ProctileHumanreadable string `json:"-"`

	// Finished is the flag to say that it is done processing
	// Extras
	Finished bool `json:"-"`
}

func (a *AuditMessage) InitAuditMessage(line string) {
	a.AuditIDRaw = ParseAuditRuleRegex(msgRule, line, "")

	if a.AuditIDRaw != "" && len(a.AuditIDRaw) > 20 {
		a.Timestamp = a.AuditIDRaw[6:20]
		a.AuditID = a.AuditIDRaw[21:]
		a.AuditID = strings.Trim(a.AuditID, ")")
	} else {
		return
	}
	// fmt.Printf("%s\t%s\n", a.Timestamp, a.AuditID)

	// gross code. Take the regex from above along with the line and the key to remove
	if out := ParseAuditRuleRegex(terminalRule, line, "terminal="); out != "" {
		a.Tty = out
	}

	if out := ParseAuditRuleRegex(ttyRule, line, "tty="); out != "" {
		a.Tty = out
	}
	if out := ParseAuditRuleRegex(exeRule, line, "exe="); out != "" {
		a.Exe = out
	}
	if out := ParseAuditRuleRegex(keyRule, line, "key="); out != "" {
		a.Key = out
	}
	if out := ParseAuditRuleRegex(pidRule, line, "pid="); out != "" {
		a.Pid = out
	}
	if out := ParseAuditRuleRegex(ppidRule, line, "ppid="); out != "" {
		a.PPid = out
	}
	// a.Name = ParseAuditRuleRegex(nameRule, line, "name=")
	// a.Proctile = ParseAuditRuleRegex(proctileRule, line, "proctitle=")
	// a.ProctileHumanreadable = string(a.Proctile)

	if out := ParseAuditRuleRegex(nameRule, line, "name="); out != "" {
		a.Name = out
	}

	if out := ParseAuditRuleRegex(proctileRule, line, "proctitle="); out != "" {
		a.Proctile = out
		// a := "2F7573722F73686172652F636F64652F636F6465202D2D756E6974792D6C61756E6368"
		bs, err := hexToStrings(out)
		if err != nil {
			log.Println(err)
		}
		// out, err := strconv.Unquote("\"" + string(bs) + "\"")
		// if err != nil {
		// 	log.Println(err)
		// }
		a.Proctile = strings.Join(bs, "\x00")

	}

	if out := ParseAuditRuleRegex(nameRule, line, "uid="); out != "" {
		a.Uid = out
	}

	if out := ParseAuditRuleRegex(auidRule, line, "auid="); out != "" {
		// a.Auid = ParseAuditRuleRegex(auidRule, line, "auid=")
		a.Auid = out

		// user, err := user.LookupId(a.Auid)
		// if err != nil {
		// 	log.Println(err)
		// } else {
		// 	a.AuidHumanReadable = user.Username
		// }
	}

	if out := ParseAuditRuleRegex(auidRuleAlpha, line, "AUID="); out != "" {
		a.AuidHumanReadable = out
	}
}

func ParseAuditRuleRegex(rules *regexp.Regexp, msg string, remove string) string {
	// apply regex magic. Maybe could be better
	value := rules.Find([]byte(msg))

	/*
		The code below is necessary due to regex shenanigans. In order to use regex with lookaheads it violates golang's regex library promise to be o(n)
		Subsequently we must comply and write the following code to remove the characters upto the equal
		I could use regex+match second group but this works just fine!
		https://groups.google.com/g/golang-nuts/c/7qgSDWPIh_E
	*/

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
