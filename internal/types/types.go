package types

type Config struct {
	Global    GlobalConfigurations `yaml:"global"`
	AbuseDBIP AbuseDBIP            `yaml:"abuse_db_ip"`
	Cpanel    Cpanel               `yaml:"cpanel"`
	CSF       CSF                  `yaml:"csf"`
	Sophos    Sophos               `yaml:"sophos"`
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
type AbuseDBIP struct {
	Enable      bool     `yaml:"enable"`
	Limit       int      `yaml:"limit"`
	Ipv6        bool     `yaml:"ipv6"`
	Ipv4        bool     `yaml:"ipv4"`
	Interval    int      `yaml:"interval"`
	ResultsFile string   `yaml:"results_file"`
	ApiKeys     []string `yaml:"api_keys"`
}

type Cpanel struct {
	enable bool     `yaml:"enable"`
	Users  []string `yaml:"users"`
}

type CSF struct {
	Enable  bool   `yaml:"enable"`
	Ipv6    bool   `yaml:"ipv6"`
	Ipv4    bool   `yaml:"ipv4"`
	Backup  bool   `yaml:"backup"`
	CSFFile string `yaml:"csf_file"`
}

type Sophos struct {
	Enable    bool   `yaml:"enable"`
	Ipv6      bool   `yaml:"ipv6"`
	Ipv4      bool   `yaml:"ipv4"`
	Interval  int    `yaml:"interval"`
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	User      string `yaml:"user"`
	Password  string `yaml:"password"`
	GroupName string `yaml:"group_name"`
	Comment   string `yaml:"comment"`
}

type UserData struct {
	IPFilePath string
	CSF        bool
	APIKey     string
	Config     string
}
