package csf

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
	"go.uber.org/zap"
)

// CSF - store the csf configuration
type CSF struct {
	Enable         bool        `yaml:"enable"`             //Enable/Disable csf module
	Backup         string      `yaml:"backup_file"`        //Csf deny file backup path
	CSFFile        string      `yaml:"csf_deny_file"`      //Csf deny file path
	CSFConfFile    string      `yaml:"csf_conf_file"`      //Csf conf file path
	ConfFileBackup string      `yaml:"csf_conf_file_back"` //Csf conf file backup path
	CsfIpLimit     int         `yaml:"csf_ip_limit"`       //Csf ip limit to set
	Ipv6           bool        //Ipv6 support
	Ipv4           bool        //Ipv4 support
	Logger         *zap.Logger //Csf logger
}

// csfClient - csf client to communicate with the user
type csfClient struct {
	csf               CSF //Csf configurations
	currentCsfIPLimit int //Runtime csf IP limit
}

// New - initialize the csf module
// Args: [CSF - csf configurations]
// Return: [csfClient]
func New(csfConf CSF) *csfClient {
	var client csfClient
	client.csf = csfConf
	// check cpanel service is active
	if err := client.IsCsfServiceActive(); err != nil {
		log.Fatal(e.MakeErr(nil, err))
	}

	// backup csf.deny and csf.conf files
	if err := client.CsfBackup(); err != nil {
		log.Fatal(e.MakeErr(nil, err))
	}

	if err := client.setCurrentCsfIpLimit(); err != nil {
		log.Fatal(e.MakeErr(nil, err))
	}

	return &client
}

// IsCsfInstalled - check if csf service is installed
func (c csfClient) IsCsfInstalled() (bool, error) {
	output, _, err := helpers.ExecuteCommand(true, "systemctl", "status", "csf.service")
	if err != nil {
		return false, e.MakeErr("error ocurred while running the command: systemctl status csf.service ", err)
	}
	if strings.Contains(output, "could not be found") {
		return false, nil
	}
	return true, nil
}

// CsfBackup - create csf backup file
func (c csfClient) CsfBackup() error {
	if err := helpers.CopyFile(c.csf.CSFConfFile, c.csf.ConfFileBackup); err != nil {
		return e.MakeErr(e.CSF_DENY_BACKUP_ERR, err)
	}
	if err := helpers.CopyFile(c.csf.CSFFile, c.csf.Backup); err != nil {
		return e.MakeErr(e.CSF_DENY_BACKUP_ERR, err)
	}
	return nil
}

// IsCsfServiceActive - check if the csf service is active
func (c *csfClient) IsCsfServiceActive() error {
	output, _, err := helpers.ExecuteCommand(true, "systemctl", "is-active", "csf.service")
	if err != nil {
		return err
	}
	if strings.Contains(output, "inactive") {
		return e.MakeErr(e.INACTIVE_CSF_SERVICE, nil)
	}
	return nil
}

func (c *csfClient) setCurrentCsfIpLimit() error {
	csfLimitStr, err := helpers.SearchRegex(c.csf.CSFConfFile, `^\s*DENY_IP_LIMIT\s*=\s*"(\d+)"\s*$`)
	if err != nil {
		return err
	}
	c.currentCsfIPLimit, err = strconv.Atoi(csfLimitStr)
	if err != nil {
		return err
	}
	if c.currentCsfIPLimit == 0 {
		return e.MakeErr(fmt.Sprintf("%s - %s", e.UNKNOWN_CSF_IP_LIMIT, c.csf.CSFConfFile), nil)
	}
	return nil
}

func (c *csfClient) getCsfDenyLength() (int, error) {
	return helpers.CountNonCommentLines(c.csf.CSFFile)
}

func (c *csfClient) setNewCsfIpLimit(limit int) error {
	return helpers.SearchAndReplace(c.csf.CSFConfFile, "DENY_IP_LIMIT =", fmt.Sprintf("DENY_IP_LIMIT = \"%d\"", limit))
}

func (c *csfClient) csfRestart(rollbackOnFailure bool) error {
	_, exitCode, err := helpers.ExecuteCommand(true, "systemctl", "restart", "csf.service")
	if err != nil {
		return err
	}

	if exitCode != 0 {
		if rollbackOnFailure {
			c.csfRollback()
		}
		return err
	}

	if err := c.IsCsfServiceActive(); err != nil {
		if rollbackOnFailure {
			c.csfRollback()
		}
		return err
	}

	return nil
}

func (c *csfClient) blockIP(ip string) error {
	text := fmt.Sprintf("%s # Added by Abuse-shield on %s", ip, time.Now().Format("2 Jan 2006 15:04:05"))
	return helpers.FileAppend(c.csf.CSFFile, text, true)
}

func (c *csfClient) csfRollback() {
	if err := helpers.CopyFile(c.csf.Backup, c.csf.CSFFile); err != nil {
		log.Fatalf("Failed to rollback\n%v", err)
	}
	if err := helpers.CopyFile(c.csf.ConfFileBackup, c.csf.CSFConfFile); err != nil {
		log.Fatalf("Failed to rollback\n%v", err)
	}
	if err := c.csfRestart(false); err != nil {
		log.Fatalf("Failed to rollback\n%v", err)
	}
}

func (c *csfClient) CsfHandler(csfDenyChan chan string, errWriter *e.SharedError) {
	for ip := range csfDenyChan {
		if err := c.blockIP(ip); err != nil {
			errWriter.SetError(err)
		}
	}

	csfDenyLength, err := c.getCsfDenyLength()
	if err != nil {
		errWriter.SetError(err)
	}

	if (csfDenyLength > c.currentCsfIPLimit) && (c.csf.CsfIpLimit == -1) {
		err = c.setNewCsfIpLimit(csfDenyLength)
	} else if c.csf.CsfIpLimit != 0 && c.csf.CsfIpLimit != -1 {
		err = c.setNewCsfIpLimit(c.csf.CsfIpLimit)
	}
	if err != nil {
		errWriter.SetError(err)
	}

	if err := c.setCurrentCsfIpLimit(); err != nil {
		errWriter.SetError(err)
	}
	if c.currentCsfIPLimit < csfDenyLength {
		fmt.Println("warning - csf deny have X ips while the csf ip limit is: Z, some ips will not be blocked")
	}

	if err := c.csfRestart(true); err != nil {
		errWriter.SetError(err)
	}
}
