package cpanel

type Cpanel struct {
	Enable bool     `yaml:"enable"`
	Users  []string `yaml:"users"`
}
