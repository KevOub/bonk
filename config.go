package main

import (
	"encoding/json"
	"io/ioutil"
)

type Config struct {
	Users    []string `json:"allowed-user"`
	Rules    []string `json:"rules"`
	Bonkable []string `json:"bonkable"`
}

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

func (config Config) AllowedUser(allowMe string) bool {

	for _, user := range config.Users {
		if allowMe == user {
			return true
		}
	}
	return false
}

func (config Config) IsBonkable(allowMe string) bool {
	for _, key := range config.Bonkable {
		if allowMe == key {
			return true
		}
	}
	return false
}
