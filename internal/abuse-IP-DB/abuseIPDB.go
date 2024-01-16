package abuseipdb

import (
	"github.com/shimon-git/AbuseShield/internal/helpers"
)

type AbuseDBIP struct {
	Enable      bool     `yaml:"enable"`
	Limit       int      `yaml:"limit"`
	Ipv6        bool     `yaml:"ipv6"`
	Ipv4        bool     `yaml:"ipv4"`
	Interval    int      `yaml:"interval"`
	ResultsFile string   `yaml:"results_file"`
	ApiKeys     []string `yaml:"api_keys"`
}

type T struct {
	M []string
}

func (a AbuseDBIP) IPCheckLimit() (int, error) {
	ip := helpers.GenerateDummyIP()
	return 0, nil
}

// create a function  that get the channel and send requests to check the ip score
func Test(c chan string, x *T) {
	for i := range c {
		x.M = append(x.M, i)
	}
}
