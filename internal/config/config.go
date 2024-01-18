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

type Config struct {
	Global    GlobalConfigurations `yaml:"global"`
	AbuseDBIP abuseipdb.AbuseDBIP  `yaml:"abuse_db_ip"`
	Cpanel    cpanel.Cpanel        `yaml:"cpanel"`
	CSF       csf.CSF              `yaml:"csf"`
	Sophos    sophos.Sophos        `yaml:"sophos"`
}

type GlobalConfigurations struct {
	Ipv6       bool     `yaml:"ipv6"`
	Ipv4       bool     `yaml:"ipv4"`
	IPsFiles   []string `yaml:"ips_file"`
	Interval   int      `yaml:"interval"`
	LogEnable  bool     `yaml:"log_enable"`
	LogFile    string   `yaml:"log_file"`
	MaxLogSize int      `yaml:"max_log_size"`
}

func Init() (Config, error) {

}

// parse the yaml config file
func ParseConfig(configFile string) (Config, error) {
	var config Config
	configReader, err := os.ReadFile(configFile)
	if err != nil {
		return config, e.MakeErr(fmt.Sprintf("%s: %s", e.CONFIG_READER_ERR, configFile), err)
	}

	if err := yaml.Unmarshal(configReader, &config); err != nil {
		return Config{}, e.MakeErr(nil, err)
	}

	return config, nil
}
