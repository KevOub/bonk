package main

import (
	"fmt"

	"github.com/KevOub/bonk/pkg/bonk"
)

func test(a bonk.AuditMessageBonk, b bonk.Config) {
	fmt.Printf("%s\n", a.AuditID)
}

func main() {

	var parser bonk.AuditMessageBonk
	var config bonk.Config

	bonk.StreamAudit(parser, config, test)
}
