package config

import (
	"context"
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

// isValidIPFile - validate if the ip file exist and the format is valid
func (c *Config) isValidIPFile(ipFiles string) error {
	var wg sync.WaitGroup
	var err error

	if len(c.Global.IPsFiles) == 0 && ipFiles == "" {
		return nil
	}

	if len(c.Global.IPsFiles) == 0 {
		c.Global.IPsFiles = strings.Split(strings.TrimSpace(ipFiles), ",")
	}

	// loop over the ip files and validate them
	for _, file := range c.Global.IPsFiles {
		// check the ip file exist
		if !helpers.IsExist(file, true) {
			return e.MakeErr(e.MISSING_IP_FILE, nil)
		}
		// create a data channel
		dataChan := make(chan string, 10)
		// add one job to the wait group
		wg.Add(1)

		ctx := context.Background()

		// start goroutine to validate the ip file format
		go ipFormatValidation(dataChan, &wg, filepath.Base(file), &err)
		// start goroutine to read the ip file
		go helpers.FileReader(ctx, file, dataChan)
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

	if len(mode) == 0 {
		return e.MakeErr(e.MISSING_MODE, nil)
	}

	// split the modes(in case of multiply modes)
	modes := strings.Split(strings.TrimSpace(mode), ",")

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

	// if cpanel is not enabled and ip files to check has not been provided then return an error
	if !c.Cpanel.Enable && len(c.Global.IPsFiles) == 0 {
		return e.MakeErr(e.MISSING_IP_FILE, nil)
	}

	return nil
}

func (c *Config) isSophosValid() error {
	// set default sophos port if port has not been provided
	if c.Sophos.Port == 0 {
		c.Sophos.Port = DEFAULT_SOPHOS_PORT
	}
	// set default sophos user if user has not been provided
	if c.Sophos.User == "" {
		c.Sophos.User = DEFAULT_SOPHOS_USER
	}

	// create sophos client
	sophosClient := sophos.New(c.Sophos)
	// verify sophos connectivity
	if err := sophosClient.VerifyConnection(); err != nil {
		return err
	}
	return nil
}

func (c *Config) isCpanelValid(cpanelUsers string) error {
	// create new cpanel client
	cpanelClient := cpanel.New(c.Cpanel, true)
	// check if cpanel is installed
	if err := cpanelClient.IsCpanelInstalled(); err != nil {
		return err
	}

	helpers.ColorPrint("cpanel installation has been detected successfully\n", "green")

	// if cpanel all users check is enabled
	if c.Cpanel.CheckAllUsers {
		// we don't need to check if cpanel users exist because we want to collect and check access log for all users
		return nil
	}
	if len(c.Cpanel.Users) == 0 {
		c.Cpanel.Users = strings.Split(strings.TrimSpace(cpanelUsers), ",")
	}

	if len(c.Cpanel.Users) == 0 {
		return e.MakeErr(e.MISSING_CPANEL_USERS, nil)
	}

	helpers.ColorPrint(fmt.Sprintf("cpanel users: [ %s ]\n", strings.Join(c.Cpanel.Users, ", ")), "green")
	return cpanelClient.IsCpanelUsersExists()

}

func (c Config) isCsfValid() error {
	// set default csf file if csf file has not been provided
	if c.CSF.CSFFile == "" {
		c.CSF.CSFFile = DEFAULT_CSF_FILE
	}
	// set default csf backup file if csf backup file has not been provided
	if c.CSF.Backup == "" {
		c.CSF.Backup = DEFAULT_CSF_BACKUP
	}
	// check if csf file exist
	if !helpers.IsExist(c.CSF.CSFFile, true) {
		return e.MakeErr(e.CSF_FILE_NOT_FOUND, nil)
	}

	// create new cpanel client - for csf validation is occurred on init
	csf.New(c.CSF)

	return nil
}

func (c *Config) isValidAbuseDB(apiKeys string) error {
	// set default blacklist file if blacklist file has not been provided
	if c.AbuseIPDB.BlackListFile == "" {
		c.AbuseIPDB.BlackListFile = DEFAULT_BLACKLIST_FILE
	}
	// set default whitelist file if whitelist file has not been provided
	if c.AbuseIPDB.WhiteListFile == "" {
		c.AbuseIPDB.WhiteListFile = DEFAULT_WHITELIST_FILE
	}
	// set default score if score has not been provided
	if c.AbuseIPDB.Score == 0 {
		c.AbuseIPDB.Score = DEFAULT_SCORE
	}

	// validating the api key length is not 0
	if len(apiKeys) != 0 {
		c.AbuseIPDB.ApiKeys = strings.Split(strings.TrimSpace(apiKeys), ",")
	}

	if len(c.AbuseIPDB.Exclude.Networks) > 0 {
		for _, network := range c.AbuseIPDB.Exclude.Networks {
			if strings.HasSuffix(network, "/32") || strings.HasSuffix(network, "/128") {
				ip := strings.Split(network, "/")[0]
				i := net.ParseIP(ip)
				if i == nil {
					return e.MakeErr(fmt.Sprintf("%s, network: %s", e.INVALID_IP_OR_NETWORK, network), nil)
				}
			}
			_, cidr, err := net.ParseCIDR(network)
			if err != nil {
				return err
			}

			if cidr.String() != network {
				return e.MakeErr(fmt.Sprintf("%s, abuseipdb excluded network: %s", e.INVALID_IP_OR_NETWORK, network), nil)
			}
		}
	}

	if len(c.AbuseIPDB.Exclude.Domains) > 0 {
		for _, domain := range c.AbuseIPDB.Exclude.Domains {
			if _, err := net.LookupIP(domain); err != nil {
				return e.MakeErr(fmt.Sprintf("%s: %s", e.UNRESOLVABLE_DOMAIN, domain), err)
			}
		}
	}

	if len(c.AbuseIPDB.ApiKeys) == 0 {
		return e.MakeErr(e.MISSING_API_KEYS, nil)
	}
	c.AbuseIPDB.ApiKeys = helpers.UniqSlice(c.AbuseIPDB.ApiKeys)

	_, err := abuseipdb.New(c.AbuseIPDB, true)

	return err
}

func (c *Config) isLogsConfValid() error {
	// set fields in case of missing fields
	if c.Logs.LogFile == "" {
		c.Logs.LogFile = DEFAULT_LOG_FILE
	}
	if c.Logs.Level == "" {
		c.Logs.Level = DEFAULT_LOG_LEVEL
	}
	// split path to log folder
	dirPath := strings.Split(c.Logs.LogFile, "/")
	// create the log folder if the folder those not exist
	if err := os.MkdirAll(strings.Join(dirPath[:len(dirPath)-1], "/"), 0755); err != nil {
		return err
	}

	// check if the provided log file path is valid
	logFile, err := os.OpenFile(c.Logs.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer logFile.Close()
	return nil
}
func (c *Config) isValidGlobalConf() error {
	if !c.Global.Ipv4 && !c.Global.Ipv6 {
		return e.MakeErr(e.IPV6_AND_IPV4_NOT_ENABLED, nil)
	}

	c.AbuseIPDB.Ipv4 = c.Global.Ipv4
	c.Sophos.Ipv4 = c.Global.Ipv4
	c.CSF.Ipv4 = c.Global.Ipv4

	c.AbuseIPDB.Ipv6 = c.Global.Ipv6
	c.Sophos.Ipv6 = c.Global.Ipv6
	c.CSF.Ipv6 = c.Global.Ipv6

	// if the global interval is not the default then set the global modes flags
	if c.Global.Interval < MINIMUM_INTERVAL {
		c.Global.Interval = MINIMUM_INTERVAL
	}

	// set global interval
	if c.Sophos.Interval == DEFAULT_INTERVAL && c.Global.Interval != DEFAULT_INTERVAL {
		c.Sophos.Interval = c.Global.Interval
	}
	if c.AbuseIPDB.Interval == DEFAULT_INTERVAL && c.Global.Interval != DEFAULT_INTERVAL {
		c.AbuseIPDB.Interval = c.Global.Interval
	}

	// validating max threads number
	switch {
	case c.Global.MaxThreads > 10:
		c.Global.MaxThreads = 10
	case c.Global.MaxThreads < 1:
		c.Global.MaxThreads = 1
	}

	return nil
}
