package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
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

func (f Flags) isValidIPFile() (bool, error) {
	var wg sync.WaitGroup
	var err error
	_, err = os.Stat(f.IPFilePath)
	if err != nil {
		return false, fmt.Errorf("%s", e.MakeErr(fmt.Sprintf("%s: %s", e.RETRIEVE_FILE_INFO_ERR, f.IPFilePath), err))
	}
	wg.Add(1)
	dataChan := make(chan string, 10)
	// check later the error package MakeErr func - its not provide the func name in the err
	go func(c chan string, fname string, err *error) {
		var counter int
		for ip := range c {
			if !isValidIP(ip) {
				counter++
				*err = e.MakeErr(nil, fmt.Errorf("%s - ip: %s- file: %s line: %s", e.IP_IS_NOT_VALID, ip, fname, counter))
			}
		}
	}(dataChan, f.IPFilePath, &err)
	helpers.IPFileReader(f.IPFilePath, dataChan, &wg)
	wg.Wait()
	close(dataChan)
	if err != nil {
		return false, err
	}
	return true, nil
}

func isValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.IsGlobalUnicast()
}

func (f Flags) isValidPhoneNumber(num string) bool {

}

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
