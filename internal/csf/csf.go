package csf

type CSF struct {
	Enable  bool   `yaml:"enable"`
	Ipv6    bool   `yaml:"ipv6"`
	Ipv4    bool   `yaml:"ipv4"`
	Backup  bool   `yaml:"backup"`
	CSFFile string `yaml:"csf_file"`
}
