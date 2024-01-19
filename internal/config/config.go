package config

import (
	"fmt"
	"os"

	abuseipdb "github.com/shimon-git/AbuseShield/internal/abuse-IP-DB"
	"github.com/shimon-git/AbuseShield/internal/cpanel"
	"github.com/shimon-git/AbuseShield/internal/csf"
	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/sophos"
	"gopkg.in/yaml.v3"
)

type configurations struct {
	Global    globalConfigurations `yaml:"global"`
	AbuseDBIP abuseipdb.AbuseDBIP  `yaml:"abuse_db_ip"`
	Cpanel    cpanel.Cpanel        `yaml:"cpanel"`
	CSF       csf.CSF              `yaml:"csf"`
	Sophos    sophos.Sophos        `yaml:"sophos"`
}

type globalConfigurations struct {
	Ipv6       bool     `yaml:"ipv6"`
	Ipv4       bool     `yaml:"ipv4"`
	IPsFiles   []string `yaml:"ips_file"`
	Interval   int      `yaml:"interval"`
	LogEnable  bool     `yaml:"log_enable"`
	LogFile    string   `yaml:"log_file"`
	MaxLogSize int      `yaml:"max_log_size"`
}

//func Init() (Config, error) {
//}

// parse the yaml config file
func (c Config) parseConfigFile() error {
	var conf configurations
	configReader, err := os.ReadFile(c.ConfigFile)
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s", e.CONFIG_READER_ERR, c.ConfigFile), err)
	}

	if err := yaml.Unmarshal(configReader, &conf); err != nil {
		e.MakeErr(nil, err)
	}

	return nil
}
