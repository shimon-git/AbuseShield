package config

import (
	"fmt"
	"os"

	e "github.com/shimon-git/AbuseShield/internal/errors"
	"gopkg.in/yaml.v3"
)

// globalConfigurations - store the global configurations
type globalConfigurations struct {
	Ipv6       bool     `yaml:"ipv6"`
	Ipv4       bool     `yaml:"ipv4"`
	IPsFiles   []string `yaml:"ip_files"`
	Interval   int      `yaml:"interval"`
	SMS        string   `yaml:"phone"`
	Email      string   `yaml:"email"`
	ErrorFile  string   `yaml:"error_file"`
	MaxThreads int      `yaml:"max_threads"`
}

// parseConfigFile - parse a given config file(yaml format) and return an error(if ocurred)
func (c *Config) parseConfigFile() error {

	// read the config file and check for errors
	configReader, err := os.ReadFile(c.ConfigFile)
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s", e.CONFIG_READER_ERR, c.ConfigFile), err)
	}
	// extract the configurations from the config file into the configurations struct and check for errors
	if err := yaml.Unmarshal(configReader, c); err != nil {
		e.MakeErr(nil, err)
	}

	return nil
}
