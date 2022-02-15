package main

import (
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"reflect"
	"strings"

	"github.com/nxadm/tail"
)

var (
	RULESPATH = "/etc/audit/rules.d/audit.rules"
	LOGSPATH  = "/var/log/audit/audit.log"
)

//go:embed good.rules
var embeddedRules []byte

//go:embed bonk.art
var bonkArt []byte

// turns regex rule to human readable

func embedOurRules(rulesPath string) {
	// os.O_TRUNC empties the file on opening
	// currentRules, err := os.OpenFile(RULESPATH, os.O_TRUNC, 0777)
	currentRules, err := os.OpenFile(rulesPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0777)
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

func clearLogs(logsPath string) {
	f, err := os.OpenFile(logsPath, os.O_TRUNC, 0777)
	if err != nil {
		log.Fatalf("Failed to yeet the contents of %s:%v", logsPath, err)
	}
	f.Truncate(0)
	stat, err := f.Stat()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(stat.Size())
	f.Close()
}

func bonkProc(line *tail.Line, key string, userToNotKill string) {
	pid := ParseAuditRuleRegex(pidRule, string(line.Text), "pid=")

	commandRan := ParseAuditRuleRegex(exeRule, string(line.Text), "exe=")

	ttyName := ParseAuditRuleRegex(ttyRule, string(line.Text), "tty=")
	auidName := ParseAuditRuleRegex(auidRule, string(line.Text), "AUID=")

	// terminalName := ParseAuditRuleRegex(terminalRule, string(line.Text), "terminal=")

	// ppid := ParseAuditRuleRegex(ppidRule, string(line.Text), "ppid=")

	fmt.Printf("key : %s\n\t TERMINAL:\t%s\tPID:\t%s\tCOMMAND:\t%s\tauid:\t%s", key, ttyName, pid, commandRan, auidName)
	fmt.Print("---\n")

	/*
	   AUID:
	   Records the Audit user ID. This ID is assigned to a user upon login and is inherited by every process even when the user's identity changes (for example, by switching user accounts with su - john).
	*/
	if auidName != userToNotKill && auidName != "root" {
		commandBuilder := fmt.Sprintf("kill -9 %s", pid)
		runCMD(commandBuilder, "failed to kill a pid")
		// runCMD(commandBuilder, "failed to kill a pid")
	}

}

func main() {
	// userToNotKill := flag.String("user", "sysadmin", "the user to not kill with bonk")
	// configPath := flag.String("cf", "/etc/bonk/bonk.yaml", "the kill switch file of sorts")

	flag.Parse()

	// viper.SetConfigName("config")    // name of config file (without extension)
	// viper.SetConfigType("yaml")      // REQUIRED if the config file does not have the extension in the name
	// viper.AddConfigPath(*configPath) // path to look for the config file in. By default it is in /etc/bonk/bonk.yaml

	// err := viper.ReadInConfig() // Find and read the config file
	// if err != nil {             // Handle errors reading the config file
	// 	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
	// 		// Config file not found; ignore error if desired
	// 		fmt.Println("[*] No extra configs set")
	// 	} else {
	// 		// Config file was found but another error was produced
	// 		panic(err)
	// 	}
	// }

	embedOurRules(RULESPATH)
	fmt.Println("[*] Embedded our rules")
	runCMD("augenrules --load", "failed to add rules")
	fmt.Println("[*] reloaded the rules")
	runCMD("service auditd rotate", "failed to rotate logs")
	clearLogs(LOGSPATH)
	fmt.Println("[*] Cleared logs")
	runCMD("pkill -HUP auditd", "failed to restart auditd")
	fmt.Println("[*] restarted the service")

	t, err := tail.TailFile(
		LOGSPATH, tail.Config{Follow: true, ReOpen: true})
	if err != nil {
		panic(err)
	}

	// extra line just to print bonk boi
	fmt.Println(string(bonkArt))

	// var bonkableOffenses = []string{
	// 	"unauthedfileaccess", "perm_mod", "etcpasswd", "etcgroup", "opasswd", "group_modification", "user_modification", "pam", "specialfiles", "cron", // modify users, touch cron or pam
	// 	"sshd", "systemd", // touch systemd or ssh config files bonk
	// 	"power",                                           // do not turn off our computers
	// 	"priv_esc",                                        // su, sudo, sudoers, sudoers.d
	// 	"susp_activity",                                   // wget, curl, base64, nc, netcat, ssh*, scp*, sftp*, ftp*, socat, wireshark, tshark, rawshark, rdesktop, nmap
	// 	"sbin_susp",                                       // iptables, ip6tables, ifconfig*, arptables*,tcpdump, ufw*...
	// 	"shell_profiles",                                  // modifying any of these: /etc/profile.d/ /etc/profile /etc/shells  /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/fish/ /etc/zsh/
	// 	"software_mgmt",                                   // apt -> dnf -> yum -> dpkg -> snap -> pip3* , all killed
	// 	"data_injection", "register_injection", "tracing"} // if they try to get cute and inject via ptrace we will know

	// The one's with the stars will probably be removed

	// "recon",                                           // whoami*, id*, hostname*, uname*, issue*, hostname*
	// recon broke ssh because of the ssh banner

	var a AuditMessage
	var prevID string
	// Print the text of each received line
	for line := range t.Lines {
		a.InitAuditMessage(line.Text)
		// fmt.Println(line.Text)
		if prevID == "" {
			prevID = a.AuditID
		}

		if prevID != a.AuditID {
			fmt.Printf("\n")
			s := reflect.ValueOf(&a).Elem()
			typeOfT := s.Type()

			fmt.Printf("\n%s\n", line.Text)
			for i := 0; i < s.NumField(); i++ {
				f := s.Field(i)
				fmt.Printf("%d: %s %s = %v\n", i,
					typeOfT.Field(i).Name, f.Type(), f.Interface())
			}

		}

		// key := ParseAuditRuleRegex(keyRule, string(line.Text), "key=")

		// for _, offense := range bonkableOffenses {
		// 	if a.Key == offense {
		// 		bonkProc(line, a.Key, *userToNotKill)
		// 	}
		// }

	}

}
