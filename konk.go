package main

// code from https://github.com/slackhq/go-audit

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"reflect"
	"strings"
	"time"
)

//go:embed good.rules
var embeddedRules []byte

const (
	// RULESPATH = "/etc/audit/rules.d/audit.rules"
	RULESPATH = "/etc/audit/rules.d/audit.rules"
	LOGSPATH  = "/var/log/bonk/bonk.log"
)

// embedOurRules
func embedOurRules() {
	// os.O_TRUNC empties the file on opening
	// currentRules, err := os.OpenFile(RULESPATH, os.O_TRUNC, 0777)
	currentRules, err := os.OpenFile(RULESPATH, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_TRUNC, 0777)
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
		} else {
			fmt.Print(err)
		}
	}
}

func bonkProc(a AuditMessage) {

	commandBuilder := fmt.Sprintf("kill -9 %s", a.Pid)
	runCMD(commandBuilder, "failed to kill a pid")

}

func init() {
	embedOurRules()
	// runCMD("augenrules --load", "failed to add rules")
	time.Sleep(1 * time.Second)

	file, err := os.OpenFile(LOGSPATH, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	log.SetOutput(file)
}

func main() {

	// bonkCurrentUser := flag.Bool("kys", "false", "use kys if you want the user running this script to be bonked")
	// bonkUserProtection := flag.String("user", "sysadmin", "any other user not to bonk") // TODO make this multi optional
	// level of bonking is a future flag
	// verboseFlag := flag.Bool("v", true, "whether to dump data to stdout or to suppress it")

	// flag.Parse()

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

	nlClient, err := NewNetlinkClient(0)
	if err != nil {
		log.Fatal(err)
	}

	var a AuditMessage

	prevID := ""

	for {
		msg, err := nlClient.Receive()
		if err != nil {
			fmt.Printf("Error during message receive: %+v\n", err)
			continue
		}

		if msg == nil {
			continue
		}

		if strings.HasPrefix(string(msg.Data), "audit") {
			a.InitAuditMessage(string(msg.Data))
			if prevID == "" {
				prevID = a.AuditID
			}
			// fmt.Println(string(msg.Data))
		}

		// fmt.Println(string(msg.Data))
		// fmt.Println("---")

		if prevID != a.AuditID && a.Key != "" {

			log.Println(string(msg.Data))

			fmt.Printf("\n")
			s := reflect.ValueOf(&a).Elem()
			typeOfT := s.Type()

			fmt.Printf("\n%s\n", string(msg.Data))
			for i := 0; i < s.NumField(); i++ {
				f := s.Field(i)
				fmt.Printf("%d: %s %s = %v\n", i,
					typeOfT.Field(i).Name, f.Type(), f.Interface())
			}

			// finally bonk the process if applicable

			for _, offense := range bonkableOffenses {
				if a.Key == offense {
					currentUser, err := user.Current()
					if err != nil {
						fmt.Print(err)
					}

					if a.Auid != currentUser.Uid && a.Auid != "root" {
						bonkProc(a)
					}
				}
			}
		}
	}
}
