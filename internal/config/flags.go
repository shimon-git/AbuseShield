package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Flags struct {
	IPFilePath string
	CSF        bool
	APIKey     string
	Config     string
	Mode       string
	Email      string
	SMS        string
}

func getFlags() Flags {
	var f Flags
	flag.StringVar(&f.IPFilePath, "ip-file", "", "Path to the IP file to check")
	flag.StringVar(&f.IPFilePath, "i", "", "Alias for --ip-file")

	flag.BoolVar(&f.CSF, "csf", false, "Enable CSF integration for automating blocking of malicious IPs")

	flag.StringVar(&f.APIKey, "api-key", "", "Set API key to use")

	flag.StringVar(&f.Config, "config", "", "Path to config file")
	flag.StringVar(&f.Config, "c", "", "Alias for --config")

	flag.StringVar(&f.Mode, "mode", "a", "Enable modes(e.g, s(sophos),a(abuseDBIP),cp(Cpanel))")
	flag.StringVar(&f.Mode, "m", "", "Alias for --mode")

	flag.StringVar(&f.Email, "email", "", "Send an email to the provided address when finished")
	flag.StringVar(&f.SMS, "sms", "", "Send SMS message to the provided phone number when finished")
	flag.Parse()

	// Check ip file path has been given
	if f.IPFilePath == "" && f.Config == "" || f.Mode == "" {
		fmt.Printf("Usage: %s --ip-file [ip-file-to-check]\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	return f
}

func (Flags) isValidIPFile(ipFile string) bool {
	return true
}

func (Flags) isValidPhoneNumber(num string) bool {}

func (Flags) isValidEmail() bool {}

// isValidMode - check if the provided mode is valid
func (f Flags) isValidMode() bool {
	validModes := map[string]bool{"cp": true, "a": true, "s": true}
	// split the modes
	modes := strings.Split(f.Mode, ",")
	for _, m := range modes {
		if _, ok := validModes[m]; !ok {
			return false
		}
	}
	return true
}
