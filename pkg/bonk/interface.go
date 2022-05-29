package bonk

import (
	"regexp"
)

// TODO replace parser with a better, more flexible parser
type Parser interface {
	IsNewAuditID(line string) bool
	InitAuditMessage(line string) error
	ParseAuditRuleRegex(rules *regexp.Regexp, msg string, remove string) string
}

// DONT REWRITE THE CONFIG. IT WORKS
