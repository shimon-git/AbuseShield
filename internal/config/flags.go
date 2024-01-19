package config

import (
	"flag"
	"fmt"

	abuseipdb "github.com/shimon-git/AbuseShield/internal/abuse-IP-DB"
	"github.com/shimon-git/AbuseShield/internal/cpanel"
	"github.com/shimon-git/AbuseShield/internal/csf"
	"github.com/shimon-git/AbuseShield/internal/sophos"
)

type Flags struct {
	IPFilePath string
	Config     string
	Mode       string
	Email      string
	SMS        string
	Sophos     sophos.Sophos
	Cpanel     cpanel.Cpanel
	CSF        csf.CSF
	AbuseDBIP  abuseipdb.AbuseDBIP
	Global     GlobalConfigurations
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

	INTERVAL_FORMAT = "%s %d %s"
)

var (
	tempApiKeys string
	tempUsers   string
)

func getFlags() Flags {
	var f Flags

	f.GetFilesFlags()
	f.GetEmailAndSMSFlags()
	f.GetModeFlags()
	f.getSophosFlags()
	f.getCpanelAndCpanelFlags()
	f.GetAbuseDBFlags()
	f.getGlobalFlags()

	flag.Parse()
	return f
}

func (f Flags) getSophosFlags() {
	flag.StringVar(&f.Sophos.Host, "host", "", "Sophos fw host IP address")
	flag.IntVar(&f.Sophos.Port, "port", DEFAULT_SOPHOS_PORT, fmt.Sprintf("%s %d", "Sophos fw port - default port is", DEFAULT_SOPHOS_PORT))
	flag.StringVar(&f.Sophos.User, "user", DEFAULT_SOPHOS_USER, fmt.Sprintf("%s %s", "Username to connect to sophos fw - default is", DEFAULT_SOPHOS_USER))
	flag.StringVar(&f.Sophos.Password, "password", "", "Password to connect to sophos fw")
	flag.IntVar(&f.Sophos.Interval, "sophos-interval", DEFAULT_INTERVAL, fmt.Sprintf(INTERVAL_FORMAT, "Interval between API requests for avoiding overload on the sophos fw server - default is", DEFAULT_INTERVAL, "seconds"))
	flag.StringVar(&f.Sophos.GroupName, "group-name", "", "Group name to add the ip addresses in sophos(new group will created if the group not exits)")
	flag.StringVar(&f.Sophos.Comment, "comment", "", "Comment to set for each new object that will created on the sophos fw server")

	flag.StringVar(&f.Sophos.Host, "h", "", "Alias for --host")
	flag.IntVar(&f.Sophos.Port, "p", DEFAULT_SOPHOS_PORT, "Alias for --port")
	flag.StringVar(&f.Sophos.User, "U", "", "Alias for --user")
	flag.StringVar(&f.Sophos.Password, "P", "", "Alias for --password")
	flag.StringVar(&f.Sophos.GroupName, "g", "", "Alias for --group-name")
	flag.StringVar(&f.Sophos.Comment, "C", "", "Alias for --comment")
}

func (f Flags) getCpanelAndCpanelFlags() {
	flag.StringVar(&tempUsers, "cpanel-users", "", "Cpanel users to collect the logs and check for abuse")
	flag.StringVar(&f.CSF.CSFFile, "csf-file", DEFAULT_CSF_FILE, fmt.Sprintf("%s %s", "Path to csf.deny file - default", DEFAULT_CSF_FILE))
	flag.StringVar(&f.CSF.Backup, "csf-backup", DEFAULT_CSF_BACKUP, fmt.Sprintf("%s %s", "Path to csf backup file(in case csf backup file already exist then it will be recreated) - default", DEFAULT_CSF_BACKUP))
}
func (f Flags) getGlobalFlags() {
	flag.BoolVar(&f.Global.Ipv4, "ipv4", DEFAULT_IPV4, fmt.Sprintf("%s %v", "Check ipv4(if is set to false ipv4 addresses will not be checked) - default is", DEFAULT_IPV4))
	flag.BoolVar(&f.Global.Ipv6, "ipv6", DEFAULT_IPV6, fmt.Sprintf("%s %v", "Check ipv6(if is set to true ipv6 addresses will be checked) - default is", DEFAULT_IPV6))
	flag.IntVar(&f.Global.Interval, "interval", DEFAULT_INTERVAL, fmt.Sprintf(INTERVAL_FORMAT, "Global interval between API requests to abusedb-ip or sophos fw - default is", DEFAULT_INTERVAL, "seconds"))
	flag.IntVar(&f.Global.Interval, "i", DEFAULT_INTERVAL, "Alias for --interval")
}

func (f Flags) GetAbuseDBFlags() {
	flag.IntVar(&f.AbuseDBIP.Limit, "limit", DEFAULT_LIMIT, "IP limit to check(limit can be set to check max number of ip addresses)")
	flag.IntVar(&f.AbuseDBIP.Interval, "abusedb-interval", DEFAULT_INTERVAL, fmt.Sprintf("%s %d %s", "Interval between API requests to not be blocked by yhe abuse-db-ip - default is", DEFAULT_INTERVAL, "seconds"))
	flag.StringVar(&f.AbuseDBIP.ResultsFile, "results", DEFAULT_RESULTS, fmt.Sprintf("%s %s", "Path to the results file of abuse-db-ip - default is", DEFAULT_RESULTS))
	flag.StringVar(&tempApiKeys, "api-keys", "", "API keys to authenticate to abuse-db-ip")
}

func (f Flags) GetFilesFlags() {
	flag.StringVar(&f.IPFilePath, "ip-file", "", "Path to the IP file to check")
	flag.StringVar(&f.IPFilePath, "I", "", "Alias for --ip-file")

	flag.StringVar(&f.Config, "config", "", "Path to config file")
	flag.StringVar(&f.Config, "c", "", "Alias for --config")
}

func (f Flags) GetModeFlags() {
	flag.StringVar(&f.Mode, "mode", "a", "Enable modes(e.g, s(sophos),a(abuseDBIP),cp(Cpanel))")
	flag.StringVar(&f.Mode, "m", "", "Alias for --mode")
}

func (f Flags) GetEmailAndSMSFlags() {
	flag.StringVar(&f.Email, "email", "", "Send an email to the provided address when finished")
	flag.StringVar(&f.SMS, "sms", "", "Send SMS message to the provided phone number when finished")
}

/*
	// Check ip file path has been given
	if f.IPFilePath == "" && f.Config == "" || f.Mode == "" {
		fmt.Printf("Usage: %s --ip-file [ip-file-to-check]\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	} */
