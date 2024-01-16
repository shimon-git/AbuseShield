package sophos

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
