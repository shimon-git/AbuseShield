package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/badoux/checkmail"
	"github.com/nyaruka/phonenumbers"
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

// isValidIPFile - validate the ip file is exist and the format is valid
func (f Flags) isValidIPFile() (bool, error) {
	var wg sync.WaitGroup
	var err error

	// check the ip file exist
	_, err = os.Stat(f.IPFilePath)
	if err != nil {
		return false, fmt.Errorf("%s", e.MakeErr(fmt.Sprintf("%s: %s", e.RETRIEVE_FILE_INFO_ERR, f.IPFilePath), err))
	}

	// create a data channel
	dataChan := make(chan string, 10)
	// add one job to the wait group
	wg.Add(1)

	// start goroutine to validate the ip file format
	go ipFormatValidation(dataChan, &wg, filepath.Base(f.IPFilePath), &err)
	// start goroutine to read the ip file
	go helpers.IPFileReader(f.IPFilePath, dataChan)
	// wait the job(the goroutine job will ended)
	wg.Wait()
	// check for errors(in case of ip file format error the goroutine ipFormatValidation will set an error)
	if err != nil {
		return false, err
	}
	// return the results(ip file and ip format is ok)
	return true, nil
}

// isValidIP - validate if the given ip is a valid ip
func isValidIP(ip string) bool {
	// parse the ip(return true if the ip is valid)
	parsedIP := net.ParseIP(ip)
	// return true if the ip is valid and normal(e.g. not special case such as: 0.0.0.0 ,etc)
	return parsedIP != nil && parsedIP.IsGlobalUnicast()
}

// isValidPhoneNumber - validate the given phone number
func (f Flags) isValidPhoneNumber() (bool, error) {
	// Parse the phone number "ZZ" for unknown region
	phone, err := phonenumbers.Parse(f.SMS, "ZZ")
	// Check for errors
	if err != nil {
		return false, e.MakeErr(fmt.Sprintf("%s - %s", e.INVALID_PHONE_NUMBER, f.SMS), err)
	}
	// get the country code
	countryCode := phonenumbers.GetRegionCodeForNumber(phone)
	// return if the phone number is valid or not
	return phonenumbers.IsValidNumberForRegion(phone, countryCode), nil
}

// isValidEmail - validate the given email address
func (f Flags) isValidEmail() (bool, error) {
	// validate the mx record of the domain
	if err := checkmail.ValidateMX(f.Email); err != nil {
		return false, e.MakeErr(nil, err)
	}
	// validate the email format
	if err := checkmail.ValidateFormat(f.Email); err != nil {
		return false, e.MakeErr(nil, err)
	}
	// return the results
	return true, nil
}

// isValidMode - check if the provided mode is valid
func (f Flags) isValidMode() bool {
	// possible modes - (cp - cpanel mode),(a - abuseDBIP mode), (s - sophos mode)
	validModes := map[string]bool{"cp": true, "a": true, "s": true}
	// split the modes(in case of multiply modes)
	modes := strings.Split(f.Mode, ",")
	// loop over the given modes and validate each mode
	for _, m := range modes {
		if _, ok := validModes[m]; !ok {
			return false
		}
	}
	// return the results
	return true
}

/*
* ipFormatValidation - validate the ip format of the provided ip file
* params:
* c - channel to collect the ip addresses from the reader
* wg - reference to the wait group for sync with the parent function
* fname - in case of error pass the file name for informative error message
* err - reference to the error to set the error message
 */
func ipFormatValidation(c chan string, wg *sync.WaitGroup, fname string, err *error) {
	// initial a counter
	var counter int
	// loop over the ip's provided by the channel
	for ip := range c {
		// increase the counter
		counter++
		// check if the ip is valid
		if !isValidIP(ip) {
			*err = e.MakeErr(nil, fmt.Errorf("%s - ip: %s- file: %s line: %s", e.IP_IS_NOT_VALID, ip, fname, counter))
		}
	}
	// done the job
	wg.Done()
}
