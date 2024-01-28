package config

import (
	"flag"

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

var (
	tempApiKeys     string //temp variable to store api keys before parsing them
	tempCpanelUsers string //temp variable to store cpanel users before parsing them
	tempMode        string //temp variable to store modes(cpanel || abuse db ip || csf || sophos) before parsing them
	tempIPFiles     string //temp variable to hold ip files path before parsing them
)

// GetConfig - return the configurations
func GetConfig() Config {
	var c Config // config to return

	// override the default Usage message
	flag.Usage = func() {
		printUsageMessage()
	}

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

/*
getSophosFlags - get the sophos flags:
flags: --host && --port && --user && password && --sophos-interval && group-name && comment)
aliases: -h for host, -p for port, -U for user, -P for password, -g for group name, -C for comment
*/
func (c *Config) getSophosFlags() {
	flag.StringVar(&c.Sophos.Host, SOPHOS_HOST_FLAG, "", sophosHostUsageMessage)
	flag.IntVar(&c.Sophos.Port, SOPHOS_PORT_FLAG, DEFAULT_SOPHOS_PORT, sophosPortUsageMessage)
	flag.StringVar(&c.Sophos.User, SOPHOS_USER_FLAG, DEFAULT_SOPHOS_USER, sophosUserUsageMessage)
	flag.StringVar(&c.Sophos.Password, SOPHOS_PASSWORD_FLAG, "", sophosPasswordUsageMessage)
	flag.IntVar(&c.Sophos.Interval, SOPHOS_INTERVAL_FLAG, DEFAULT_INTERVAL, sophosIntervalUsageMessage)
	flag.StringVar(&c.Sophos.GroupName, SOPHOS_GROUP_FLAG, "", sophosGroupUsageMessage)
	flag.StringVar(&c.Sophos.Comment, SOPHOS_COMMENT_FLAG, "", sophosCommentUsageMessage)

	flag.StringVar(&c.Sophos.Host, SOPHOS_HOST_ALIAS_FLAG, "", sophosHostAliasUsageMessage)
	flag.IntVar(&c.Sophos.Port, SOPHOS_PORT_ALIAS_FLAG, DEFAULT_SOPHOS_PORT, sophosPortAliasUsageMessage)
	flag.StringVar(&c.Sophos.User, SOPHOS_USER_ALIAS_FLAG, DEFAULT_SOPHOS_USER, sophosUserAliasUsageMessage)
	flag.StringVar(&c.Sophos.Password, SOPHOS_PASSWORD_ALIAS_FLAG, "", sophosPasswordAliasUsageMessage)
	flag.StringVar(&c.Sophos.GroupName, SOPHOS_GROUP_ALIAS_FLAG, "", sophosGroupAliasUsageMessage)
	flag.StringVar(&c.Sophos.Comment, SOPHOS_COMMENT_ALIAS_FLAG, "", sophosCommentAliasUsageMessage)
}

/*
getCsfAndCpanelFlags - get the csf and cpanel flags:
flags: --cpanel-users && --cpanel-all-users && --csf-file && --csf-backup
aliases: None
*/
func (c *Config) getCsfAndCpanelFlags() {
	flag.StringVar(&tempCpanelUsers, CPANEL_USERS_FLAG, "", cpanelUsersUsageMessage)
	flag.BoolVar(&c.Cpanel.CheckAllUsers, CPANEL_CHECK_ALL_USERS_FLAG, DEFAULT_CHECK_ALL_CPANEL_USERS, cpanelAllUsersUsageMessage)
	flag.StringVar(&c.CSF.CSFFile, CSF_FILE_FLAG, DEFAULT_CSF_FILE, csfFileUsageMessage)
	flag.StringVar(&c.CSF.Backup, CSF_BACKUP_FILE_FLAG, DEFAULT_CSF_BACKUP, csfBackupFileUsageMessage)
}

/*
getGlobalFlags - get the global configuration flags:
flags: --ipv4 && --ipv6 && --interval
aliases: -i for --interval
*/
func (c *Config) getGlobalFlags() {
	flag.BoolVar(&c.Global.Ipv4, GLOBAL_IPV4_FLAG, DEFAULT_IPV4, globalIPv4UsageMessage)
	flag.BoolVar(&c.Global.Ipv6, GLOBAL_IPV6_FLAG, DEFAULT_IPV6, globalIPv6UsageMessage)
	flag.IntVar(&c.Global.Interval, GLOBAL_INTERVAL_FLAG, DEFAULT_INTERVAL, globalIntervalUsageMessage)
	flag.IntVar(&c.Global.Interval, GLOBAL_INTERVAL_ALIAS_FLAG, DEFAULT_INTERVAL, globalIntervalAliasUsageMessage)
}

/*
GetAbuseDBFlags - get the abuse  configuration flags:
flags: --limit && --abuseipdb-interval && --results && --api-keys && --score
aliases: None
*/
func (c *Config) GetAbuseDBFlags() {
	flag.IntVar(&c.AbuseIPDB.Limit, ABUSE_DB_IP_LIMIT_FLAG, DEFAULT_LIMIT, abuseIPDBLimitUsageMessage)
	flag.IntVar(&c.AbuseIPDB.Interval, ABUSE_DB_IP_INTERVAL_FLAG, DEFAULT_INTERVAL, abuseIPDBIntervalUsageMessage)
	flag.StringVar(&c.AbuseIPDB.BlackListFile, ABUSE_DB_IP_BLACKLIST_FLAG, DEFAULT_BLACKLIST_FILE, abuseIPDBBlacklistUsageMessage)
	flag.StringVar(&c.AbuseIPDB.WhiteListFile, ABUSE_DB_IP_WHITELIST_FLAG, DEFAULT_WHITELIST_FILE, abuseIPDBWhitelistUsageMessage)
	flag.StringVar(&tempApiKeys, ABUSE_DB_IP_API_KEYS_FLAG, "", abuseIPDBAPIKeysUsageMessage)
	flag.IntVar(&c.AbuseIPDB.Score, ABUSE_DB_IP_SCORE_FLAG, DEFAULT_SCORE, abuseIPDBScoreUsageMessage)
}

/*
GetFilesFlags - get the config file and ip files flags:
flags: --ip-file && --config
aliases: -I for --ip-file
*/
func (c *Config) GetFilesFlags() {
	flag.StringVar(&tempIPFiles, IP_FILE_FLAG, "", ipFilesUsageMessage)
	flag.StringVar(&tempIPFiles, IP_FILE_ALIAS_FLAG, "", ipFilesAliasUsageMessage)

	flag.StringVar(&c.ConfigFile, CONFIG_FILE_FLAG, "", configFileUsageMessage)
	flag.StringVar(&c.ConfigFile, CONFIG_FILE_ALIAS_FLAG, "", configFileAliasUsageMessage)
}

/*
GetModeFlags - get the modes(a - abuseIPDB, s - sophos, cp - cpanel, c - csf) configurations flags:
flags: --mode
aliases: -m for --mode
*/
func (c *Config) GetModeFlags() {
	flag.StringVar(&tempMode, MODE_FLAG, "", modeUsageMessage)
	flag.StringVar(&tempMode, MODE_ALIAS_FLAG, "", modeAliasUsageMessage)
}

/*
GetModeFlags - get email and phone flags:
flags: --email --sms
aliases: None
*/
func (c *Config) GetEmailAndSMSFlags() {
	flag.StringVar(&c.Global.Email, EMAIL_FLAG, "", emailUsageMessage)
	flag.StringVar(&c.Global.SMS, SMS_FLAG, "", smsUsageMessage)
}
