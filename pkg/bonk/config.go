package bonk

import (
	"encoding/json"
	"io/ioutil"
	"strings"
)

// BonkOperation is the Operation needed to be performed
type BonkOperation int64

const (
	LOAD        BonkOperation = iota // Operation for loading rules
	LOCKANDLOAD                      // Bad name for loading rules then using bonk
	DELETE                           // Operation for deleting all rules
	HONK                             // Operation for showing what would be killed but doesn't
	BONK                             // Kill violations
)

// the options specified via config.json
type Config struct {
	BadIPs   []string `json:"banned-ips"`
	GoodIPs  []string `json:"allowed-ips"`
	Users    []string `json:"allowed-user"`
	Rules    []string `json:"rules"`
	Bonkable []string `json:"bonkable"`
	ConfigRuntime
}

// the options specified by flags (and in theory config.json)
type ConfigRuntime struct {
	Operation      BonkOperation `json:"-"`
	EmbeddedRules  []byte        `json:"-"`
	DenyListMode   bool          `json:"deny-by-ip"`
	AllowListMode  bool          `json:"allow-by-ip"`
	DontEmbedRules bool          `json:"embed-rules"`
	BonksBeforeBan int           `json:"bonks-before-ip-ban"`
	Verbose        bool          `json:"verbose"`
}

// Load Put data into Config class **not needed anymore**
func (config *Config) Load(path string) error {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(file), &config)
	if err != nil {
		return err
	}
	return nil
}

// LoadFromIO a bad name that is just unmarshalling the config file
func (config *Config) LoadFromIO(file []byte) error {
	err := json.Unmarshal([]byte(file), &config)
	if err != nil {
		return err
	}
	return nil
}

// EmbedRules a bad function that takes the bytes and assignes it to the EmbeddedRules member
func (config *Config) EmbedRules(data []byte) {
	config.EmbeddedRules = data
}

// BannedIP checks against the config if the IP is found in the DenyListMode
func (config Config) BannedIP(allowMe string) bool {

	for _, ip := range config.BadIPs {
		if strings.Contains(allowMe, ip) {
			return true
		}
	}

	return false

}

// AllowedIP checks against the config if the IP is found in the AllowListMode
func (config Config) AllowedIP(allowMe string) bool {
	for _, ip := range config.GoodIPs {
		if strings.Contains(allowMe, ip) {
			return true
		}
	}

	return allowMe == ""

}

// AllowedUser goes through all users and checks to see if the User is allowed
func (config Config) AllowedUser(allowMe string) bool {

	for _, user := range config.Users {
		if strings.Contains(allowMe, user) {
			return true
		}
	}

	return false

}

// IsBonkable goes through all keys set up by config.json and kills those which are "bonkable"
func (config Config) IsBonkable(allowMe string) bool {
	for _, key := range config.Bonkable {
		if allowMe == key {
			return true
		}
	}
	return false
}
