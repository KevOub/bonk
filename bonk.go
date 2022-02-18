package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/fatih/color"
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

func PrettyStruct(data interface{}) (string, error) {
	val, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return "", err
	}
	return string(val), nil
}

func init() {

}

func main() {
	// userToNotKill := flag.String("user", "sysadmin", "the user to not kill with bonk")
	// configPath := flag.String("cf", "/etc/bonk/bonk.yaml", "the kill switch file of sorts")
	// logPath := flag.String("out", "bonk.log", "the log file to write to")
	loadTheRules := flag.Bool("l", true, "whether to embed the files (true or false)")
	rotateLogs := flag.Bool("r", false, "rotate logs (true or false)")
	safeUser := flag.String("u", "sysadmin", "the user to *NOT* kill")
	extremeMode := flag.Bool("e", false, "EXTREME MODE (true or false)")

	flag.Parse()

	if *loadTheRules {
		embedOurRules(RULESPATH)
		fmt.Println("[*] Embedded our rules")
		runCMD("augenrules --load", "failed to add rules")
		fmt.Println("[*] reloaded the rules")
		// clearLogs(LOGSPATH)
		runCMD("pkill -HUP auditd", "failed to restart auditd")
		fmt.Println("[*] restarted the service")

	}

	if *rotateLogs {
		runCMD("service auditd rotate", "failed to rotate logs")
		clearLogs(LOGSPATH)
		fmt.Println("[*] Cleared logs")
	}

	t, err := tail.TailFile(
		LOGSPATH, tail.Config{Follow: true, ReOpen: true})
	if err != nil {
		panic(err)
	}

	// extra line just to print bonk boi
	fmt.Println(string(bonkArt))

	var bonkableOffenses = []string{}
	if *extremeMode {
		bonkableOffenses = []string{
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
	} else {
		bonkableOffenses = []string{
			"sudo", "data_injection", "register_injection", "tracing"}
	}

	var outMessage string
	var outMessagePrev string
	var a AuditMessage
	var prevID string
	var offensive bool
	// Print the text of each received line
	for line := range t.Lines {
		a.InitAuditMessage(line.Text)
		// fmt.Println(line.Text)
		if prevID == "" {
			prevID = a.AuditID
		}

		for _, offense := range bonkableOffenses {
			if a.Key == offense {
				offensive = true
				name, err := user.Lookup(*safeUser)
				if err != nil {
					log.Fatal(err)
				}

				if a.Auid != name.Uid && a.AuidHumanReadable != "root" && a.AuidHumanReadable != "unset" {
					commandBuilder := fmt.Sprintf("kill -9 %s", a.Pid)
					runCMD(commandBuilder, "failed to kill a pid")
					outMessage = fmt.Sprintf("[%s] CMD: %s;\tCMD_F: %s;\tUSER:%s\t;KEY %s\t;", color.RedString("BONK"),
						color.RedString(a.Exe), color.RedString(a.Proctile),
						color.RedString(a.AuidHumanReadable), color.RedString(a.Key))
					if outMessage != outMessagePrev {
						log.Print(outMessage)
					}
				}

				if a.Auid != name.Uid && a.Uid == "root" {
					outMessage = fmt.Sprintf("[%s] CMD: %s;\tCMD_F: %s;\tUSER:%s\t;KEY %s\t;", color.HiRedString("CRIT"),
						color.HiRedString(a.Exe), color.HiRedString(a.Proctile),
						color.HiRedString(a.AuidHumanReadable), color.HiRedString(a.Key))
					if outMessage != outMessagePrev {
						log.Print(outMessage)
					}
				}
				// else {
				// log.Printf("[%s] CMD: %s;\tCMD_F: %s;\tUSER:%s\t;KEY %s\t;", color.CyanString("FALSE"),
				// 	color.CyanString(a.Exe), color.CyanString(a.ProctileHumanreadable),
				// 	color.CyanString(a.AuidHumanReadable), color.CyanString(a.Key))
				// }

			}
		}

		if !offensive && a.Key != "" {

			outMessage = fmt.Sprintf("[%s] CMD: %s;\tCMD_F: %s;\tUSER:%s\t;KEY %s\t;", color.BlueString("INFO"),
				color.BlueString(a.Exe), color.BlueString(a.Proctile),
				color.BlueString(a.AuidHumanReadable), color.BlueString(a.Key))

			if outMessage != outMessagePrev {
				log.Print(outMessage)
			}
		}
		offensive = false

		outMessagePrev = outMessage

	}

}
