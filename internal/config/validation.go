package config

import (
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
	// possible modes - (cp - cpanel mode),(a - abuseDBIP mode), (s - sophos mode), (c - csf mode)
	validModes := map[string]bool{"cp": true, "a": true, "s": true, "c": true}
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
