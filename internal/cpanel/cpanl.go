package cpanel

type Cpanel struct {
	enable bool     `yaml:"enable"`
	Users  []string `yaml:"users"`
}
