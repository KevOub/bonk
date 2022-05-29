package main

import (
	"embed"
	_ "embed"

	"github.com/KevOub/bonk/pkg/bonk"
)

func test(a bonk.AuditMessageBonk, b bonk.Config) {
	// fmt.Printf("%+v\n", a)
	// bonk.BonkCheck()
}

// EMBEDDING LOGIC
//go:embed embed/config.json embed/good.rules
var content embed.FS

func main() {

	var parser bonk.Parser
	var config bonk.Config

	// f, _ := content.Open("embed/config.json")
	// data, _ := ioutil.ReadFile("embed/config.json")

	// take the config.json and set the config struct accordingly
	data, err := content.ReadFile("embed/config.json")
	if err != nil {
		panic(err)
	}
	config.LoadFromIO(data)

	// Here is how to embed good.rules into the struct
	defaultRules, err := content.ReadFile("embed/good.rules")
	if err != nil {
		panic(err)
	}
	config.EmbedRules(defaultRules)

	// Finally, specify operation
	config.Operation = bonk.LOCKANDLOAD
	config.DontEmbedRules = false
	config.Verbose = true
	// and enter the infinite loop
	bonk.StreamAudit(parser, config, bonk.BonkCheckVerbose)

}
