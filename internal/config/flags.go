package config

import (
	"flag"
	"fmt"
	"os"

	abuseipdb "github.com/shimon-git/AbuseShield/internal/abuse-IP-DB"
	"github.com/shimon-git/AbuseShield/internal/cpanel"
	"github.com/shimon-git/AbuseShield/internal/csf"
	"github.com/shimon-git/AbuseShield/internal/sophos"
)

// Config - type to store the configurations
type Config struct {
	ConfigFile string               //config file path
	Sophos     sophos.Sophos        //sophos conf
	Cpanel     cpanel.Cpanel        //cpanel conf
	CSF        csf.CSF              //csf conf
	AbuseIPDB  abuseipdb.AbuseIPDB  //abuse dv ip conf
	Global     globalConfigurations //global conf
}

const (
	DEFAULT_SOPHOS_PORT            = 4444                        //default sophos port
	DEFAULT_SOPHOS_USER            = "admin"                     //default sophos user
	DEFAULT_LIMIT                  = 0                           //default limit amount of ip to check
	DEFAULT_CSF_FILE               = "/etc/csf/csf.deny"         //default csf.deny file path
	DEFAULT_CSF_BACKUP             = "/tmp/csf_backup.deny"      //default csf.deny backup file path
	DEFAULT_RESULTS                = "./abuse_db_ip_results.txt" //default abuse db ip results file path
	DEFAULT_IPV4                   = true                        //default ipv4(true for enable || false for disable)
	DEFAULT_IPV6                   = false                       //default ipv6(true for enable || false for disable)
	DEFAULT_SCORE                  = 15                          //default minimum score for considering an ip as malicious
	DEFAULT_CHECK_ALL_CPANEL_USERS = false                       //default value to check all cpanel users(true for enable || false to disable)
	DEFAULT_INTERVAL               = 3                           //default interval between api requests to avoid overload
	MINIMUM_INTERVAL               = 1                           //minimum interval that can be set
)

var (
	tempApiKeys     string //temp variable to store api keys before parsing them
	tempCpanelUsers string //temp variable to store cpanel users before parsing them
	tempMode        string //temp variable to store modes(cpanel || abuse db ip || csf || sophos) before parsing them
	tempIPFiles     string //temp variable to hold ip files path before parsing them
)

// GetConfig - return the configurations
func GetConfig() Config {
	var c Config // config to return

	// get all flags and parse them
	c.GetFilesFlags()        // get the files - IP files and config file
	c.GetEmailAndSMSFlags()  // get email and phone number
	c.GetModeFlags()         // get modes to enable(e.g sophos,csf etc...)
	c.getSophosFlags()       // get sophos conf
	c.getCsfAndCpanelFlags() // get csf and cpanel conf
	c.GetAbuseDBFlags()      // get abuse db ip conf
	c.getGlobalFlags()       // get global conf
	flag.Parse()             // parse the flags

	// check if a config file has been provided
	if c.ConfigFile != "" {
		// parse the config file and check for errors
		if err := c.parseConfigFile(); err != nil {
			// print the usage and the error and exit
			printUsageAndExit(err)
		}
		// set the global configurations
		c.adjustGlobalConfigurations()
		// validate and set all configurations
		c.validateAndSetConfigurations()
		// return the config
		return c
	}

	// in case a config file has not been provided parse,validate and set the configurations
	c.validateAndSetConfigurations()
	c.adjustGlobalConfigurations()
	// return the config
	return c
}

// validateAndSetConfigurations - validate the configurations that provided by the user(except the global configurations)
func (c *Config) validateAndSetConfigurations() {
	// ip file validation
	if err := c.isValidIPFile(tempIPFiles); err != nil {
		printUsageAndExit(err)
	}

	// email validation
	if c.Global.Email != "" {
		if err := c.isValidEmail(); err != nil {
			printUsageAndExit(err)
		}
	}

	// sms validation
	if c.Global.SMS != "" {
		if err := c.isValidPhoneNumber(); err != nil {
			printUsageAndExit(err)
		}
	}

	// mode validation and setter(its will set the Enable field for the modes(sophos,csf,cpanel,abuseDBIP))
	if err := c.isValidMode(tempMode); err != nil {
		printUsageAndExit(err)
	}

	// sophos validation
	if c.Sophos.Enable {
		if err := c.isSophosValid(); err != nil {
			printUsageAndExit(err)
		}
	}
	// cpanel validation
	if c.Cpanel.Enable {
		if err := c.isCpanelValid(tempCpanelUsers); err != nil {
			printUsageAndExit(err)
		}
	}

	// csf validation
	if c.CSF.Enable {
		if err := c.isCsfValid(); err != nil {
			printUsageAndExit(err)
		}
	}

	// abuseDBIP validation
	if c.AbuseIPDB.Enable {
		if err := c.isValidAbuseDB(tempApiKeys); err != nil {
			printUsageAndExit(err)
		}
	}
}

// adjustGlobalConfigurations - validate the global configurations only
func (c *Config) adjustGlobalConfigurations() {
	// if ipv4 is false which is not the default behavior then set the global modes flags
	if !c.Global.Ipv4 {
		c.Sophos.Ipv4 = c.Global.Ipv4
		c.CSF.Ipv4 = c.Global.Ipv4
		c.AbuseIPDB.Ipv4 = c.Global.Ipv4
	}
	// if ipv6 is true which is not the default behavior then set the global modes flags
	if c.Global.Ipv6 {
		c.Sophos.Ipv6 = c.Global.Ipv6
		c.CSF.Ipv6 = c.Global.Ipv6
		c.AbuseIPDB.Ipv6 = c.Global.Ipv6
	}

	// if the global interval is not the default then set the global modes flags
	if c.Global.Interval < MINIMUM_INTERVAL {
		c.Global.Interval = DEFAULT_INTERVAL
	}
	// check if the global interval is not the default interval
	if c.Global.Interval != DEFAULT_INTERVAL {
		// set the sophos interval except if the sophos interval has been override and is valid
		if c.Sophos.Interval == DEFAULT_INTERVAL || c.Sophos.Interval < MINIMUM_INTERVAL {
			c.Sophos.Interval = c.Global.Interval
		}
		// set the abuse db ip interval except if the sophos interval has been override and is valid
		if c.AbuseIPDB.Interval == DEFAULT_INTERVAL || c.AbuseIPDB.Interval < MINIMUM_INTERVAL {
			c.AbuseIPDB.Interval = c.Global.Interval
		}
	}

	// check if a config file has been provided
	if c.ConfigFile != "" {
		// set ipv4 and ipv6 for each mode
		c.Sophos.Ipv4 = c.Global.Ipv4
		c.CSF.Ipv4 = c.Global.Ipv4
		c.AbuseIPDB.Ipv4 = c.Global.Ipv4
		c.Sophos.Ipv6 = c.Global.Ipv6
		c.CSF.Ipv6 = c.Global.Ipv6
		c.AbuseIPDB.Ipv6 = c.Global.Ipv6

		// if global interval is invalid set the global interval to the default behavior
		if c.Global.Interval < MINIMUM_INTERVAL {
			c.Global.Interval = DEFAULT_INTERVAL
		}
		// if sophos interval is invalid set the sophos interval to the global behavior
		if c.Sophos.Interval < MINIMUM_INTERVAL {
			c.Sophos.Interval = c.Global.Interval
		}
		// if abuse db ip interval is invalid set the abuse db ip interval to the global behavior
		if c.AbuseIPDB.Interval < MINIMUM_INTERVAL {
			c.AbuseIPDB.Interval = c.Global.Interval
		}
	}
}

// printUsageAndExit - print the usage and the error and exit
func printUsageAndExit(err error) {
	// print the usage
	fmt.Printf("\n%s\n\n", "--------------- USAGE ---------------")
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Printf("\n%s\n", "-------------------------------------")

	// print the error
	fmt.Printf("\n%s\n\n", "--------------- Error ---------------")
	fmt.Println(err.Error())
	fmt.Printf("%s\n", "-------------------------------------")

	// exit with error code
	os.Exit(1)
}

/*
getSophosFlags - get the sophos flags:
flags: --host && --port && --user && password && --sophos-interval && group-name && comment)
aliases: -h for host, -p for port, -U for user, -P for password, -g for group name, -C for comment
*/
func (c *Config) getSophosFlags() {
	flag.StringVar(&c.Sophos.Host, "host", "", "Sophos fw host IP address")
	flag.IntVar(&c.Sophos.Port, "port", DEFAULT_SOPHOS_PORT, fmt.Sprintf("%s %d", "Sophos fw port - default port is", DEFAULT_SOPHOS_PORT))
	flag.StringVar(&c.Sophos.User, "user", DEFAULT_SOPHOS_USER, fmt.Sprintf("%s %s", "Username to connect to sophos fw - default is", DEFAULT_SOPHOS_USER))
	flag.StringVar(&c.Sophos.Password, "password", "", "Password to connect to sophos fw")
	flag.IntVar(&c.Sophos.Interval, "sophos-interval", DEFAULT_INTERVAL, fmt.Sprintf("%s %d %s", "Interval between API requests for avoiding overload on the sophos fw server - default is", DEFAULT_INTERVAL, "seconds"))
	flag.StringVar(&c.Sophos.GroupName, "group-name", "", "Group name to add the ip addresses in sophos(new group will created if the group not exits)")
	flag.StringVar(&c.Sophos.Comment, "comment", "", "Comment to set for each new object that will created on the sophos fw server")

	flag.StringVar(&c.Sophos.Host, "h", "", "Alias for --host")
	flag.IntVar(&c.Sophos.Port, "p", DEFAULT_SOPHOS_PORT, "Alias for --port")
	flag.StringVar(&c.Sophos.User, "U", DEFAULT_SOPHOS_USER, "Alias for --user")
	flag.StringVar(&c.Sophos.Password, "P", "", "Alias for --password")
	flag.StringVar(&c.Sophos.GroupName, "g", "", "Alias for --group-name")
	flag.StringVar(&c.Sophos.Comment, "C", "", "Alias for --comment")
}

/*
getCsfAndCpanelFlags - get the csf and cpanel flags:
flags: --cpanel-users && --cpanel-all-users && --csf-file && --csf-backup
aliases: None
*/
func (c *Config) getCsfAndCpanelFlags() {
	flag.StringVar(&tempCpanelUsers, "cpanel-users", "", "Cpanel users to collect the logs and check for abuse")
	flag.BoolVar(&c.Cpanel.CheckAllUsers, "cpanel-all-users", DEFAULT_CHECK_ALL_CPANEL_USERS, "Set to true in case you want ti check abuse for all cpanel users")
	flag.StringVar(&c.CSF.CSFFile, "csf-file", DEFAULT_CSF_FILE, fmt.Sprintf("%s %s", "Path to csf.deny file - default", DEFAULT_CSF_FILE))
	flag.StringVar(&c.CSF.Backup, "csf-backup", DEFAULT_CSF_BACKUP, fmt.Sprintf("%s %s", "Path to csf backup file(in case csf backup file already exist then it will be recreated) - default", DEFAULT_CSF_BACKUP))
}

/*
getGlobalFlags - get the global configuration flags:
flags: --ipv4 && --ipv6 && --interval
aliases: -i -- for the global interval
*/
func (c *Config) getGlobalFlags() {
	flag.BoolVar(&c.Global.Ipv4, "ipv4", DEFAULT_IPV4, fmt.Sprintf("%s %v", "Check ipv4(if is set to false ipv4 addresses will not be checked) - default is", DEFAULT_IPV4))
	flag.BoolVar(&c.Global.Ipv6, "ipv6", DEFAULT_IPV6, fmt.Sprintf("%s %v", "Check ipv6(if is set to true ipv6 addresses will be checked) - default is", DEFAULT_IPV6))
	flag.IntVar(&c.Global.Interval, "interval", DEFAULT_INTERVAL, fmt.Sprintf("%s %d %s", "Global interval between API requests to abusedb-ip or sophos fw - default is", DEFAULT_INTERVAL, "seconds"))
	flag.IntVar(&c.Global.Interval, "i", DEFAULT_INTERVAL, "Alias for --interval")
}

func (c *Config) GetAbuseDBFlags() {
	flag.IntVar(&c.AbuseIPDB.Limit, "limit", DEFAULT_LIMIT, "IP limit to check(limit can be set to check max number of ip addresses)")
	flag.IntVar(&c.AbuseIPDB.Interval, "abusedb-interval", DEFAULT_INTERVAL, fmt.Sprintf("%s %d %s", "Interval between API requests to not be blocked by yhe abuse-db-ip - default is", DEFAULT_INTERVAL, "seconds"))
	flag.StringVar(&c.AbuseIPDB.ResultsFile, "results", DEFAULT_RESULTS, fmt.Sprintf("%s %s", "Path to the results file of abuse-db-ip - default is", DEFAULT_RESULTS))
	flag.StringVar(&tempApiKeys, "api-keys", "", "API keys to authenticate to abuse-db-ip")
	flag.IntVar(&c.AbuseIPDB.Score, "score", DEFAULT_SCORE, fmt.Sprintf("%s: %d", "Minimum IP score to considered as malicious IP(score can be set from 1 - 100) - default is", DEFAULT_SCORE))
}

func (c *Config) GetFilesFlags() {
	flag.StringVar(&tempIPFiles, "ip-file", "", "Path to the IP file to check")
	flag.StringVar(&tempIPFiles, "I", "", "Alias for --ip-file")

	flag.StringVar(&c.ConfigFile, "config", "", "Path to config file")
	flag.StringVar(&c.ConfigFile, "c", "", "Alias for --config")
}

func (c *Config) GetModeFlags() {
	flag.StringVar(&tempMode, "mode", "a", "Enable modes(s(sophos),a(abuseDBIP),cp(Cpanel),c(csf))")
	flag.StringVar(&tempMode, "m", "", "Alias for --mode")
}

func (c *Config) GetEmailAndSMSFlags() {
	flag.StringVar(&c.Global.Email, "email", "", "Send an email to the provided address when finished")
	flag.StringVar(&c.Global.SMS, "sms", "", "Send SMS message to the provided phone number when finished")
}
