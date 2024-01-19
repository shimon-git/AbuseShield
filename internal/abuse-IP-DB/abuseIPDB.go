package abuseipdb

type AbuseDBIP struct {
	Enable      bool     `yaml:"enable"`
	Limit       int      `yaml:"limit"`
	Ipv6        bool     `yaml:"ipv6"`
	Ipv4        bool     `yaml:"ipv4"`
	Interval    int      `yaml:"interval"`
	ResultsFile string   `yaml:"results_file"`
	ApiKeys     []string `yaml:"api_keys"`
}
