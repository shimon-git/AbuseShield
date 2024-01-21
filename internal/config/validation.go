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
	abuseipdb "github.com/shimon-git/AbuseShield/internal/abuse-IP-DB"
	"github.com/shimon-git/AbuseShield/internal/cpanel"
	"github.com/shimon-git/AbuseShield/internal/csf"
	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
	"github.com/shimon-git/AbuseShield/internal/sophos"
)

func isFileExist(f string) error {
	_, err := os.Stat(f)
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s", e.RETRIEVE_FILE_INFO_ERR, f), err)
	}
	return nil
}

// isValidIPFile - validate if the ip file exist and the format is valid
func (c Config) isValidIPFile(ipFiles string) error {
	var wg sync.WaitGroup
	var err error

	if len(c.Global.IPsFiles) == 0 && tempIPFiles == "" {
		return e.MakeErr(e.MISSING_IP_FILE, nil)
	}

	if len(c.Global.IPsFiles) == 0 {
		c.Global.IPsFiles = strings.Split(strings.TrimSpace(tempIPFiles), ",")
	}

	// loop over the ip files and validate them
	for _, file := range c.Global.IPsFiles {
		// check the ip file exist
		if err := isFileExist(file); err != nil {
			return err
		}
		// create a data channel
		dataChan := make(chan string, 10)
		// add one job to the wait group
		wg.Add(1)

		// start goroutine to validate the ip file format
		go ipFormatValidation(dataChan, &wg, filepath.Base(file), &err)
		// start goroutine to read the ip file
		go helpers.IPFileReader(file, dataChan)
		// wait the job(the goroutine job will ended)
		wg.Wait()
		// check for errors(in case of ip file format error the goroutine ipFormatValidation will set an error)
		if err != nil {
			return err
		}
	}

	// return the results(ip file and ip format is ok)
	return nil
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
			*err = e.MakeErr(nil, fmt.Errorf("%s - ip: %s- file: %s line: %d", e.IP_IS_NOT_VALID, ip, fname, counter))
			// done the job
			wg.Done()
			return
		}
	}
	// done the job
	wg.Done()
}

// isValidIP - validate if the given ip is a valid ip
func isValidIP(ip string) bool {
	ipParts := strings.Split(ip, "/")

	// Check if CIDR part exists
	if len(ipParts) > 1 {
		ip = ipParts[0]
		cidr := ipParts[1]

		// parse the ip (return false if the ip is not valid)
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return false
		}

		_, ipNet, err := net.ParseCIDR(ip + "/" + cidr)
		if err != nil {
			return false
		}

		// Check if the IP is within the specified CIDR range
		return ipNet.Contains(parsedIP)
	}

	// If there is no CIDR part, consider it a valid IP
	return net.ParseIP(ip) != nil
}

// isValidPhoneNumber - validate the given phone number
func (c Config) isValidPhoneNumber() error {
	// Parse the phone number "ZZ" for unknown region
	phone, err := phonenumbers.Parse(c.Global.SMS, "ZZ")
	// Check for errors
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s - %s", e.INVALID_PHONE_NUMBER, c.Global.SMS), err)
	}
	// get the country code
	countryCode := phonenumbers.GetRegionCodeForNumber(phone)
	// return if the phone number is valid or not
	if phonenumbers.IsValidNumberForRegion(phone, countryCode) {
		return nil
	}
	return e.MakeErr(fmt.Sprintf("%s: %s", e.INVALID_PHONE_NUMBER, phone), nil)
}

// isValidEmail - validate the given email address
func (c Config) isValidEmail() error {
	// validate the mx record of the domain
	if err := checkmail.ValidateMX(c.Global.Email); err != nil {
		return e.MakeErr(nil, err)
	}
	// validate the email format
	if err := checkmail.ValidateFormat(c.Global.Email); err != nil {
		return e.MakeErr(nil, err)
	}
	// return the results
	return nil
}

// isValidMode - check if the provided mode is valid(possible modes - (cp - cpanel mode),(a - abuseDBIP mode), (s - sophos mode), (c - csf mode))
func (c *Config) isValidMode(mode string) error {
	if c.ConfigFile != "" {
		if !c.AbuseIPDB.Enable && !c.CSF.Enable && !c.Cpanel.Enable && !c.Sophos.Enable {
			return e.MakeErr(e.NO_MODULES_ENABLED, nil)
		}
		if (c.CSF.Enable || c.Cpanel.Enable) && !c.AbuseIPDB.Enable {
			return e.MakeErr(e.ABUSE_DB_IP_NOT_ENABLED, nil)
		}
		return nil
	}

	// split the modes(in case of multiply modes)
	modes := strings.Split(strings.TrimSpace(mode), ",")

	if len(modes) == 0 {
		return e.MakeErr(e.MISSING_MODE, nil)
	}
	// loop over the given modes and validate each mode
	for i := 0; i < len(modes); i++ {
		switch modes[i] {
		// cpanel mode
		case "cp":
			c.Cpanel.Enable = true
		// abuseDBIP mode
		case "a":
			c.AbuseIPDB.Enable = true
		// csf mode
		case "c":
			c.CSF.Enable = true
		// sophos mode
		case "s":
			c.Sophos.Enable = true
		// invalid mode
		default:
			return e.MakeErr(fmt.Sprintf("%s: %s", e.INVALID_MODE, modes[i]), nil)
		}
	}
	if (c.CSF.Enable || c.Cpanel.Enable) && !c.AbuseIPDB.Enable {
		return e.MakeErr(e.ABUSE_DB_IP_NOT_ENABLED, nil)
	}
	return nil
}

func (c *Config) isSophosValid() error {
	sophosClient := sophos.New(c.Sophos)
	if err := sophosClient.VerifyConnection(); err != nil {
		return err
	}
	return nil
}

func (c *Config) isCpanelValid(cpanelUsers string) error {
	c.Cpanel.Users = strings.Split(strings.TrimSpace(cpanelUsers), ",")
	if len(c.Cpanel.Users) == 0 {
		return e.MakeErr(e.MISSING_CPANEL_USERS, nil)
	}

	cpanelClient := cpanel.New(c.Cpanel)
	if err := cpanelClient.IsAllUsersExists(); err != nil {
		return err
	}
	return nil
}

func (c Config) isCsfValid() error {
	if err := isFileExist(c.CSF.CSFFile); err != nil {
		return err
	}
	csfClient := csf.New(c.CSF)

	if err := csfClient.CsfBackup(); err != nil {
		return err
	}
	if err := csfClient.IsCsfServiceActive(); err != nil {
		return err
	}
	return nil
}

func (c *Config) isValidAbuseDB(apiKeys string) error {
	if len(apiKeys) != 0 {
		c.AbuseIPDB.ApiKeys = strings.Split(strings.TrimSpace(apiKeys), ",")
	}

	if len(c.AbuseIPDB.ApiKeys) == 0 {
		return e.MakeErr(e.MISSING_API_KEYS, nil)
	}
	c.AbuseIPDB.ApiKeys = helpers.UniqSlice(c.AbuseIPDB.ApiKeys)

	_, err := abuseipdb.New(c.AbuseIPDB)

	return err
}
