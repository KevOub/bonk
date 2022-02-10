package main

// code from https://github.com/slackhq/go-audit

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

//go:embed good.rules
var embeddedRules []byte

// embedOurRules
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

func main() {
	embedOurRules()

	runCMD("augenrules --load", "failed to add rules")

	nlClient, err := NewNetlinkClient(0)
	if err != nil {
		log.Fatal(err)
	}

	// output needs to be created before anything that write to stdout

	for {
		msg, err := nlClient.Receive()
		if err != nil {
			fmt.Printf("Error during message receive: %+v\n", err)
			continue
		}

		if msg == nil {
			continue
		}
		fmt.Println(string(msg.Data))
		fmt.Println("---")
	}
}
