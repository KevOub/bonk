package main

import (
	_ "embed"
	"flag"
	"fmt"
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

func bonkProc(line *tail.Line, key string, userToNotKill string) {
	pid := parseAuditRuleRegex(pidRule, string(line.Text), "pid=")

	commandRan := parseAuditRuleRegex(exeRule, string(line.Text), "exe=")

	ttyName := parseAuditRuleRegex(ttyRule, string(line.Text), "tty=")
	auidName := parseAuditRuleRegex(auidRule, string(line.Text), "AUID=")

	// terminalName := parseAuditRuleRegex(terminalRule, string(line.Text), "terminal=")

	// ppid := parseAuditRuleRegex(ppidRule, string(line.Text), "ppid=")

	fmt.Printf("key : %s\n\t TERMINAL:\t%s\tPID:\t%s\tCOMMAND:\t%s\tauid:\t%s", key, ttyName, pid, commandRan, auidName)
	fmt.Print("---\n")

	/*
	   AUID:
	   Records the Audit user ID. This ID is assigned to a user upon login and is inherited by every process even when the user's identity changes (for example, by switching user accounts with su - john).
	*/
	if auidName != userToNotKill && auidName != "root" {
		commandBuilder := fmt.Sprintf("kill -9 %s", pid)
		runCMD(commandBuilder, "failed to kill a pid")
	}

}

func init() {

	embedOurRules()
	fmt.Println("[*] Embedded our rules")
	runCMD("augenrules --load", "failed to add rules")
	fmt.Println("[*] reloaded the rules")
	runCMD("service auditd rotate", "failed to rotate logs")
	clearLogs()
	fmt.Println("[*] Cleared logs")
	runCMD("pkill -HUP auditd", "failed to restart auditd")
	fmt.Println("[*] restarted the service")
}

func main() {
	userToNotKill := flag.String("user", "sysadmin", "the user to not kill with bonk")

	flag.Parse()

	t, err := tail.TailFile(
		LOGSPATH, tail.Config{Follow: true, ReOpen: true})
	if err != nil {
		panic(err)
	}

	// extra line just to print bonk boi
	fmt.Println(string(bonkArt))

	var bonkableOffenses = []string{
		"unauthedfileaccess", "perm_mod", "etcpasswd", "etcgroup", "opasswd", "group_modification", "user_modification", "pam", "specialfiles", "cron", // modify users, touch cron or pam
		"sshd", "systemd", // touch systemd or ssh config files bonk
		"power",                                           // do not turn off our computers
		"priv_esc",                                        // su, sudo, sudoers, sudoers.d
		"susp_activity",                                   // wget, curl, base64, nc, netcat, ssh*, scp*, sftp*, ftp*, socat, wireshark, tshark, rawshark, rdesktop, nmap
		"sbin_susp",                                       // iptables, ip6tables, ifconfig*, arptables*,tcpdump, ufw*...
		"shell_profiles",                                  // modifying any of these: /etc/profile.d/ /etc/profile /etc/shells  /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/fish/ /etc/zsh/
		"software_mgmt",                                   // apt -> dnf -> yum -> dpkg -> snap -> pip3* , all killed
		"data_injection", "register_injection", "tracing"} // if they try to get cute and inject via ptrace we will know

	// The one's with the stars will probably be removed
	// "recon",                                           // whoami*, id*, hostname*, uname*, issue*, hostname*
	// recon broke ssh because of the ssh banner

	// Print the text of each received line
	for line := range t.Lines {

		key := parseAuditRuleRegex(keyRule, string(line.Text), "key=")

		for _, offense := range bonkableOffenses {
			if key == offense {
				bonkProc(line, key, *userToNotKill)
			}
		}

	}

}
