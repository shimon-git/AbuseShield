package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	DEFAULT_SOPHOS_PORT            = 4444                   //default sophos port
	DEFAULT_SOPHOS_USER            = "admin"                //default sophos user
	DEFAULT_LIMIT                  = 0                      //default limit amount of ip to check
	DEFAULT_CSF_FILE               = "/etc/csf/csf.deny"    //default csf.deny file path
	DEFAULT_CSF_BACKUP             = "/tmp/csf_backup.deny" //default csf.deny backup file path
	DEFAULT_BLACKLIST_FILE         = "./blacklist.txt"      //default abuse db ip results file path
	DEFAULT_WHITELIST_FILE         = "./whitelist.txt"      //default abuse db ip results file path
	DEFAULT_IPV4                   = true                   //default ipv4(true for enable || false for disable)
	DEFAULT_IPV6                   = false                  //default ipv6(true for enable || false for disable)
	DEFAULT_SCORE                  = 15                     //default minimum score for considering an ip as malicious
	DEFAULT_CHECK_ALL_CPANEL_USERS = false                  //default value to check all cpanel users(true for enable || false to disable)
	DEFAULT_INTERVAL               = 3                      //default interval between api requests to avoid overload
	MINIMUM_INTERVAL               = 1                      //minimum interval that can be set
	DEFAULT_MAX_THREADS            = 5                      //max threads(goroutines)
)

const (
	//sophos flags
	SOPHOS_HOST_FLAG     = "host"
	SOPHOS_PORT_FLAG     = "port"
	SOPHOS_USER_FLAG     = "user"
	SOPHOS_PASSWORD_FLAG = "password"
	SOPHOS_INTERVAL_FLAG = "sophos-interval"
	SOPHOS_GROUP_FLAG    = "group-name"
	SOPHOS_COMMENT_FLAG  = "comment"
	//sophos alias flags
	SOPHOS_HOST_ALIAS_FLAG     = "H"
	SOPHOS_PORT_ALIAS_FLAG     = "p"
	SOPHOS_USER_ALIAS_FLAG     = "U"
	SOPHOS_PASSWORD_ALIAS_FLAG = "P"
	SOPHOS_GROUP_ALIAS_FLAG    = "g"
	SOPHOS_COMMENT_ALIAS_FLAG  = "C"
	//csf and cpanel flags
	CPANEL_USERS_FLAG           = "cpanel-users"
	CPANEL_CHECK_ALL_USERS_FLAG = "cpanel-all-users"
	CSF_FILE_FLAG               = "csf-file"
	CSF_BACKUP_FILE_FLAG        = "csf-backup"
	//global flags
	GLOBAL_IPV4_FLAG           = "ipv4"
	GLOBAL_IPV6_FLAG           = "ipv6"
	GLOBAL_INTERVAL_FLAG       = "interval"
	GLOBAL_INTERVAL_ALIAS_FLAG = "i"
	GLOBAL_MAX_THREADS_FLAG    = "max-threads"
	//abuse db ip  flags
	ABUSE_DB_IP_LIMIT_FLAG     = "limit"
	ABUSE_DB_IP_INTERVAL_FLAG  = "abuse-ip-db-interval"
	ABUSE_DB_IP_BLACKLIST_FLAG = "blacklist-file"
	ABUSE_DB_IP_WHITELIST_FLAG = "whitelist-file"
	ABUSE_DB_IP_API_KEYS_FLAG  = "api-keys"
	ABUSE_DB_IP_SCORE_FLAG     = "score"
	// ip files and config file flags
	IP_FILE_FLAG           = "ip-file"
	IP_FILE_ALIAS_FLAG     = "I"
	CONFIG_FILE_FLAG       = "config"
	CONFIG_FILE_ALIAS_FLAG = "c"
	// mode flags
	MODE_FLAG       = "mode"
	MODE_ALIAS_FLAG = "m"
	// notifications flags
	EMAIL_FLAG = "email"
	SMS_FLAG   = "sms"
)

var (
	// sophos usage messages
	sophosHostUsageMessage     = "IP address of the Sophos firewall host"
	sophosPortUsageMessage     = fmt.Sprintf("Port for the Sophos firewall - default port is: %d", DEFAULT_SOPHOS_PORT)
	sophosUserUsageMessage     = fmt.Sprintf("User name for Sophos firewall authentication - default user is: %s", DEFAULT_SOPHOS_USER)
	sophosPasswordUsageMessage = "Password for Sophos firewall authentication"
	sophosIntervalUsageMessage = fmt.Sprintf("Time interval (in seconds) between Sophos API requests to prevent server overload - default interval is: %d", DEFAULT_INTERVAL)
	sophosGroupUsageMessage    = "Name of the group in Sophos where IP addresses are added; creates a new group if it doesn't exist"
	sophosCommentUsageMessage  = "Comment to be added to each new object created on the Sophos firewall"
	// sophos alias usage messages
	sophosHostAliasUsageMessage     = "Short alias for --host"
	sophosPortAliasUsageMessage     = "Short alias for --port"
	sophosUserAliasUsageMessage     = "Short alias for --user"
	sophosPasswordAliasUsageMessage = "Short alias for --password"
	sophosGroupAliasUsageMessage    = "Short alias for --group-name"
	sophosCommentAliasUsageMessage  = "Short alias for --comment"
	// cpanel and csf usage messages
	cpanelUsersUsageMessage    = "Specific cPanel users to check for abuse logs"
	cpanelAllUsersUsageMessage = "Enable to check for abuse logs across all cPanel users"
	csfFileUsageMessage        = fmt.Sprintf("Path to the CSF (ConfigServer Security & Firewall) 'deny' file - default file path is: %s", DEFAULT_CSF_FILE)
	csfBackupFileUsageMessage  = fmt.Sprintf("Path for backup of CSF 'deny' file - default file path is: %s", DEFAULT_CSF_BACKUP)
	// global flags usage messages
	globalIPv4UsageMessage          = fmt.Sprintf("Enable or disable IPv4 checking - default is enabled (%t)", DEFAULT_IPV4)
	globalIPv6UsageMessage          = fmt.Sprintf("Enable or disable IPv6 checking - default is disabled (%t)", DEFAULT_IPV6)
	globalIntervalUsageMessage      = fmt.Sprintf("Global interval (in seconds) between API requests - default interval is: %d", DEFAULT_INTERVAL)
	globalIntervalAliasUsageMessage = "Short alias for --interval"
	globalMaxThreadsUsageMessage    = fmt.Sprintf("Max threads - default is: %d", DEFAULT_MAX_THREADS)
	// abuseDBIP usage messages
	abuseIPDBLimitUsageMessage     = "Maximum number of IP addresses to check against the AbuseIPDB"
	abuseIPDBIntervalUsageMessage  = fmt.Sprintf("Time interval (in seconds) between requests to AbuseIPDB to avoid being blocked - default interval is: %d", DEFAULT_INTERVAL)
	abuseIPDBBlacklistUsageMessage = fmt.Sprintf("Path for the blacklist file from AbuseIPDB queries - default interval is: %s", DEFAULT_BLACKLIST_FILE)
	abuseIPDBWhitelistUsageMessage = fmt.Sprintf("Path for the whitelist file from AbuseIPDB queries - default interval is: %s", DEFAULT_WHITELIST_FILE)
	abuseIPDBAPIKeysUsageMessage   = "API keys for authenticating requests to AbuseIPDB"
	abuseIPDBScoreUsageMessage     = fmt.Sprintf("Minimum score threshold to consider an IP as malicious (range 1-100) - default score is: %d", DEFAULT_SCORE)
	// mode flag usage messages
	modeUsageMessage      = "Select operational modes: s (Sophos), a (AbuseIPDB), cp (cPanel), c (CSF)"
	modeAliasUsageMessage = "Short alias for --mode"
	// notifications usage messages
	emailUsageMessage = "Email address to send notifications upon task completion"
	smsUsageMessage   = "Phone number to send SMS notifications upon task completion"
	// ip files and config file usage messages
	ipFilesUsageMessage         = "Path to the file containing IP addresses to be checked"
	ipFilesAliasUsageMessage    = "Short alias for --ip-file"
	configFileUsageMessage      = "Path to the application's configuration file"
	configFileAliasUsageMessage = "Short alias for --config"
)

// printUsageAndExit - print the usage and the error and exit, if error is nil no error will be printed
func printUsageAndExit(err error) {
	// print usage message
	fmt.Printf("\n%s\n\n", "--------------- USAGE ---------------")
	printUsageMessage()
	fmt.Printf("\n%s\n", "-------------------------------------")
	// print error message if error is not nil
	if err != nil {
		fmt.Printf("\n%s\n", "--------------- Error ---------------")
		fmt.Println(err.Error())
		fmt.Printf("%s\n", "-------------------------------------")
	}
	// exit
	os.Exit(1)
}

// printFlagSection prints a section of flags with a header
func printFlagSection(header string, flags []string) {
	// print the header
	fmt.Printf("\n%s:\n", header)
	// iterate over the flags and print each flag to the console
	for _, flag := range flags {
		fmt.Println(flag)
	}
}

// formatFlag formats the flag with padding for alignment
func formatFlag(flagName, usage string) string {
	// alias flag case
	if strings.Contains(strings.ToLower(usage), "alias") {
		return fmt.Sprintf("  -%-20s  %s", flagName, usage)
	}
	// return a formatted flag name and flag description
	return fmt.Sprintf("  --%-20s %s", flagName, usage)
}

// printUsageMessage - print usage message
func printUsageMessage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n", os.Args[0])

	printFlagSection("Sophos Configuration Flags", []string{
		formatFlag(SOPHOS_HOST_FLAG, sophosHostUsageMessage),
		formatFlag(SOPHOS_PORT_FLAG, sophosPortUsageMessage),
		formatFlag(SOPHOS_USER_FLAG, sophosUserUsageMessage),
		formatFlag(SOPHOS_PASSWORD_FLAG, sophosPasswordUsageMessage),
		formatFlag(SOPHOS_INTERVAL_FLAG, sophosIntervalUsageMessage),
		formatFlag(SOPHOS_GROUP_FLAG, sophosGroupUsageMessage),
		formatFlag(SOPHOS_COMMENT_FLAG, sophosCommentUsageMessage),
		formatFlag(SOPHOS_HOST_ALIAS_FLAG, sophosHostAliasUsageMessage),
		formatFlag(SOPHOS_PORT_ALIAS_FLAG, sophosPortAliasUsageMessage),
		formatFlag(SOPHOS_USER_ALIAS_FLAG, sophosUserAliasUsageMessage),
		formatFlag(SOPHOS_PASSWORD_ALIAS_FLAG, sophosPasswordAliasUsageMessage),
		formatFlag(SOPHOS_GROUP_ALIAS_FLAG, sophosGroupAliasUsageMessage),
		formatFlag(SOPHOS_COMMENT_ALIAS_FLAG, sophosCommentAliasUsageMessage),
	})

	printFlagSection("CSF and CPanel Flags", []string{
		formatFlag(CPANEL_USERS_FLAG, cpanelUsersUsageMessage),
		formatFlag(CPANEL_CHECK_ALL_USERS_FLAG, cpanelAllUsersUsageMessage),
		formatFlag(CSF_FILE_FLAG, csfFileUsageMessage),
		formatFlag(CSF_BACKUP_FILE_FLAG, csfBackupFileUsageMessage),
	})

	printFlagSection("Global Configuration Flags", []string{
		formatFlag(GLOBAL_IPV4_FLAG, globalIPv4UsageMessage),
		formatFlag(GLOBAL_IPV6_FLAG, globalIPv6UsageMessage),
		formatFlag(GLOBAL_INTERVAL_FLAG, globalIntervalUsageMessage),
		formatFlag(GLOBAL_INTERVAL_ALIAS_FLAG, globalIntervalAliasUsageMessage),
		formatFlag(GLOBAL_MAX_THREADS_FLAG, globalMaxThreadsUsageMessage),
	})

	printFlagSection("Abuse DB Configuration Flags", []string{
		formatFlag(ABUSE_DB_IP_LIMIT_FLAG, abuseIPDBLimitUsageMessage),
		formatFlag(ABUSE_DB_IP_INTERVAL_FLAG, abuseIPDBIntervalUsageMessage),
		formatFlag(ABUSE_DB_IP_BLACKLIST_FLAG, abuseIPDBBlacklistUsageMessage),
		formatFlag(ABUSE_DB_IP_WHITELIST_FLAG, abuseIPDBWhitelistUsageMessage),
		formatFlag(ABUSE_DB_IP_API_KEYS_FLAG, abuseIPDBAPIKeysUsageMessage),
		formatFlag(ABUSE_DB_IP_SCORE_FLAG, abuseIPDBScoreUsageMessage),
	})

	printFlagSection("File Configuration Flags", []string{
		formatFlag(IP_FILE_FLAG, ipFilesUsageMessage),
		formatFlag(CONFIG_FILE_FLAG, configFileUsageMessage),
		formatFlag(IP_FILE_ALIAS_FLAG, ipFilesAliasUsageMessage),
		formatFlag(CONFIG_FILE_ALIAS_FLAG, configFileAliasUsageMessage),
	})

	printFlagSection("Mode Configuration Flags", []string{
		formatFlag(MODE_FLAG, modeUsageMessage),
		formatFlag(MODE_ALIAS_FLAG, modeAliasUsageMessage),
	})

	printFlagSection("Notification Flags", []string{
		formatFlag(EMAIL_FLAG, emailUsageMessage),
		formatFlag(SMS_FLAG, smsUsageMessage),
	})
}
