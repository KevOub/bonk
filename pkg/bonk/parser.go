package bonk

import (
	"strings"
)

type Parser interface {
	Init()                   // Init() creates the map[string]string for the fields
	Parse(msg []byte) bool   // Parse() takes a byte slice and returns a bool if the message is a new audit message
	Get(key string) string   // Get() takes a key and returns the value
	List() map[string]string // List() returns the map[string]string
	NewLog(msg string) bool  // NewLog() takes a string and a previous string and returns a bool if the message is a new audit message
}

// SAMPLE INTERFACE FOR PARSING AUDIT LOGS

type AuditLogFields struct {
	Fields  map[string]string `json:"fields"`
	AuditID string            `json:"auditID"`
}

func (a *AuditLogFields) Init() {
	a.AuditID = ""
	a.Fields = make(map[string]string)
}

func (a *AuditLogFields) NewLog(msg string) bool {

	for _, word := range strings.Split(string(msg), " ") {

		// go snippet that splits the string by equal sign

		if strings.Contains(word, "audit") {
			if len(word) >= 21 {
				val := word[21:]
				val = strings.Replace(val, "):", "", -1)

				if a.AuditID == "" {
					a.AuditID = val
				} else if a.AuditID != val {
					// a.AuditID = val
					return true
				}

			}
		}
	}

	return false
}

func (a *AuditLogFields) Parse(msg []byte) bool {

	// boolean that will be returned
	// Since the parser is stateless and only parses we need to keep track
	// when the current line is a new audit message
	newentry := false

	for _, word := range strings.Split(string(msg), " ") {
		if strings.Contains(word, "=") {
			keyval := strings.Split(word, "=")
			if len(keyval) == 2 {
				a.Fields[keyval[0]] = keyval[1]
			}
		}

	}

	return newentry
}

func (a AuditLogFields) Get(key string) string {

	return a.Fields[key]
}

func (a AuditLogFields) List() map[string]string {
	return a.Fields
}
