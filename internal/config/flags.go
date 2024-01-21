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

type Config struct {
	IPFilePath string
	ConfigFile string
	Email      string
	SMS        string
	Sophos     sophos.Sophos
	Cpanel     cpanel.Cpanel
	CSF        csf.CSF
	AbuseDBIP  abuseipdb.AbuseDBIP
	Global     globalConfigurations
}

const (
	DEFAULT_SOPHOS_PORT = 4444
	DEFAULT_SOPHOS_USER = "admin"
	DEFAULT_INTERVAL    = 3
	DEFAULT_LIMIT       = 0
	DEFAULT_CSF_FILE    = "/etc/csf/csf.deny"
	DEFAULT_CSF_BACKUP  = "/tmp/csf_backup.deny"
	DEFAULT_RESULTS     = "./abuse_db_ip_results.txt"
	DEFAULT_IPV4        = true
	DEFAULT_IPV6        = false
	INTERVAL_FORMAT     = "%s %d %s"
)

var (
	tempApiKeys     string
	tempCpanelUsers string
	tempMode        string
)

func GetConfig() Config {
	var c Config
	// get the all flags and parse them
	c.GetFilesFlags()        // check
	c.GetEmailAndSMSFlags()  // check
	c.GetModeFlags()         // check
	c.getSophosFlags()       // check
	c.getCsfAndCpanelFlags() //check
	c.GetAbuseDBFlags()
	c.getGlobalFlags()
	flag.Parse()

	// config file validation
	if c.ConfigFile != "" {
		if err := c.parseConfigFile(); err != nil {
			printUsageAndExit(err)
		}
		return c
	}

	// ip file validation
	if err := c.isValidIPFile(); err != nil {
		printUsageAndExit(err)
	}

	// email validation
	if c.Email != "" {
		if err := c.isValidEmail(); err != nil {
			printUsageAndExit(err)
		}
	}

	// sms validation
	if c.SMS != "" {
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
	if c.AbuseDBIP.Enable {
		if err := c.isValidAbuseDB(tempApiKeys); err != nil {
			printUsageAndExit(err)
		}
	}

	return c
}

func printUsageAndExit(err error) {

	fmt.Printf("\n%s\n\n", "--------------- USAGE ---------------")
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Printf("\n%s\n", "-------------------------------------")
	fmt.Printf("\n%s\n\n", "--------------- Error ---------------")
	fmt.Println(err.Error())
	fmt.Printf("%s\n", "-------------------------------------")
	os.Exit(1)
}

func (c *Config) getSophosFlags() {
	flag.StringVar(&c.Sophos.Host, "host", "", "Sophos fw host IP address")
	flag.IntVar(&c.Sophos.Port, "port", DEFAULT_SOPHOS_PORT, fmt.Sprintf("%s %d", "Sophos fw port - default port is", DEFAULT_SOPHOS_PORT))
	flag.StringVar(&c.Sophos.User, "user", DEFAULT_SOPHOS_USER, fmt.Sprintf("%s %s", "Username to connect to sophos fw - default is", DEFAULT_SOPHOS_USER))
	flag.StringVar(&c.Sophos.Password, "password", "", "Password to connect to sophos fw")
	flag.IntVar(&c.Sophos.Interval, "sophos-interval", DEFAULT_INTERVAL, fmt.Sprintf(INTERVAL_FORMAT, "Interval between API requests for avoiding overload on the sophos fw server - default is", DEFAULT_INTERVAL, "seconds"))
	flag.StringVar(&c.Sophos.GroupName, "group-name", "", "Group name to add the ip addresses in sophos(new group will created if the group not exits)")
	flag.StringVar(&c.Sophos.Comment, "comment", "", "Comment to set for each new object that will created on the sophos fw server")

	flag.StringVar(&c.Sophos.Host, "h", "", "Alias for --host")
	flag.IntVar(&c.Sophos.Port, "p", DEFAULT_SOPHOS_PORT, "Alias for --port")
	flag.StringVar(&c.Sophos.User, "U", DEFAULT_SOPHOS_USER, "Alias for --user")
	flag.StringVar(&c.Sophos.Password, "P", "", "Alias for --password")
	flag.StringVar(&c.Sophos.GroupName, "g", "", "Alias for --group-name")
	flag.StringVar(&c.Sophos.Comment, "C", "", "Alias for --comment")
}

func (c *Config) getCsfAndCpanelFlags() {
	flag.StringVar(&tempCpanelUsers, "cpanel-users", "", "Cpanel users to collect the logs and check for abuse")
	flag.StringVar(&c.CSF.CSFFile, "csf-file", DEFAULT_CSF_FILE, fmt.Sprintf("%s %s", "Path to csf.deny file - default", DEFAULT_CSF_FILE))
	flag.StringVar(&c.CSF.Backup, "csf-backup", DEFAULT_CSF_BACKUP, fmt.Sprintf("%s %s", "Path to csf backup file(in case csf backup file already exist then it will be recreated) - default", DEFAULT_CSF_BACKUP))
}
func (c *Config) getGlobalFlags() {
	flag.BoolVar(&c.Global.Ipv4, "ipv4", DEFAULT_IPV4, fmt.Sprintf("%s %v", "Check ipv4(if is set to false ipv4 addresses will not be checked) - default is", DEFAULT_IPV4))
	flag.BoolVar(&c.Global.Ipv6, "ipv6", DEFAULT_IPV6, fmt.Sprintf("%s %v", "Check ipv6(if is set to true ipv6 addresses will be checked) - default is", DEFAULT_IPV6))
	flag.IntVar(&c.Global.Interval, "interval", DEFAULT_INTERVAL, fmt.Sprintf(INTERVAL_FORMAT, "Global interval between API requests to abusedb-ip or sophos fw - default is", DEFAULT_INTERVAL, "seconds"))
	flag.IntVar(&c.Global.Interval, "i", DEFAULT_INTERVAL, "Alias for --interval")
}

func (c *Config) GetAbuseDBFlags() {
	flag.IntVar(&c.AbuseDBIP.Limit, "limit", DEFAULT_LIMIT, "IP limit to check(limit can be set to check max number of ip addresses)")
	flag.IntVar(&c.AbuseDBIP.Interval, "abusedb-interval", DEFAULT_INTERVAL, fmt.Sprintf("%s %d %s", "Interval between API requests to not be blocked by yhe abuse-db-ip - default is", DEFAULT_INTERVAL, "seconds"))
	flag.StringVar(&c.AbuseDBIP.ResultsFile, "results", DEFAULT_RESULTS, fmt.Sprintf("%s %s", "Path to the results file of abuse-db-ip - default is", DEFAULT_RESULTS))
	flag.StringVar(&tempApiKeys, "api-keys", "", "API keys to authenticate to abuse-db-ip")
}

func (c *Config) GetFilesFlags() {
	flag.StringVar(&c.IPFilePath, "ip-file", "", "Path to the IP file to check")
	flag.StringVar(&c.IPFilePath, "I", "", "Alias for --ip-file")

	flag.StringVar(&c.ConfigFile, "config", "", "Path to config file")
	flag.StringVar(&c.ConfigFile, "c", "", "Alias for --config")
}

func (c *Config) GetModeFlags() {
	flag.StringVar(&tempMode, "mode", "a", "Enable modes(s(sophos),a(abuseDBIP),cp(Cpanel),c(csf))")
	flag.StringVar(&tempMode, "m", "", "Alias for --mode")
}

func (c *Config) GetEmailAndSMSFlags() {
	flag.StringVar(&c.Email, "email", "", "Send an email to the provided address when finished")
	flag.StringVar(&c.SMS, "sms", "", "Send SMS message to the provided phone number when finished")
}
