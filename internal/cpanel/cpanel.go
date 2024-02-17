package cpanel

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
	"go.uber.org/zap"
)

const (
	// a part of the cpanel account not exist error
	CPANEL_ACCOUNT_NOT_EXIST_MESSAGE_PART = "Account does not exist."
)

// Cpanel - store the cpanel module configurations
type Cpanel struct {
	Enable        bool        `yaml:"enable"`        //isModuleEnable
	Users         []string    `yaml:"users"`         //usersSlice
	CheckAllUsers bool        `yaml:"checkAllUsers"` //checkAllCpanelUsers
	Logger        *zap.Logger //cpanelLogger
}

// cpClient - cpClient to interact with the user
type cpClient struct {
	cpanel   Cpanel   //cpanelConf
	logFiles []string //cpanelUserLogFiles
}

// AccountList - store the cpanel api response
type AccountList struct {
	Data struct {
		Acct []struct {
			User string `json:"user"`
		} `json:"acct"`
	} `json:"data"`
}

// New - initialize the cpanel module
// Args: [Cpanel]
// Return: [*cpClient]
func New(c Cpanel, validation bool) *cpClient {
	if validation {
		c.Logger.Debug("initializing new cpanel module")
	} else {
		c.Logger.Info("initializing new cpanel module")
	}
	var cp cpClient
	cp.cpanel = c
	return &cp
}

// IsCpanelUsersExists - check if cpanel.Users exist on cpanel
// Return: [error in case an error occurred]
func (c *cpClient) IsCpanelUsersExists() error {
	// iterating through the users to see if the users exist on the cpanel system
	c.cpanel.Logger.Info("checking if cpanel users are exist", zap.String("cpanelUsers", fmt.Sprintf("[ %s ]", strings.Join(c.cpanel.Users, ", "))))
	for _, user := range c.cpanel.Users {
		tmpLogger := c.cpanel.Logger.With(zap.String("cpanelUser", user), zap.String("command", fmt.Sprintf("whmapi1 accountsummary --user=%s", user)))
		// running cpanel command to check if the users exist
		tmpLogger.Info("checking if the cpanel user is exist")
		output, _, err := helpers.ExecuteCommand(true, "whmapi1", "accountsummary", fmt.Sprintf("user=%s", user))
		if err != nil {
			tmpLogger.Error(err.Error())
			return err
		}

		// checking the command response to find if the user exist or not
		if strings.Contains(output, CPANEL_ACCOUNT_NOT_EXIST_MESSAGE_PART) {
			tmpLogger.Warn(fmt.Sprintf("cpanel user is not exist"))
			return e.MakeErr(fmt.Sprintf("%s: %s", e.CPANEL_USER_NOT_FOUND, user), nil)
		}
	}
	return nil
}

// IsCpanelInstalled - check if cpanel is installed on the operating system
// Return: [error in case an error occurred]
func (c *cpClient) IsCpanelInstalled() error {
	// command to check if cpanel is installed
	cmd := "/usr/local/cpanel/cpanel"

	// logs and info to console
	tmpLogger := c.cpanel.Logger.With(zap.String("command", cmd))
	tmpLogger.Debug("checking if cpanel is installed")

	// running the command
	output, exitCode, err := helpers.ExecuteCommand(true, cmd)
	if err != nil {
		tmpLogger.Error(err.Error())
		return err
	}

	// checking the exit code of the command
	if exitCode != 0 {
		tmpLogger.Error("cpanel is not installed", zap.Int("exitCode", exitCode), zap.String("commandOutput", output))
		return e.MakeErr(e.CPANEL_IN_NOT_INSTALLED, err)
	}

	c.cpanel.Logger.Info("cpanel is installed")
	return nil
}

// SetAllUsers - find and set all the cpanel users
// Return: [error in case an error occurred]
func (c *cpClient) SetAllUsers() error {
	// env map to set for the cpanel api
	env := map[string]string{
		"LC_ALL":   "",
		"LANG":     "en_US.UTF-8",
		"LANGUAGE": "en_US.UTF-8",
	}
	// iterating through the env map
	for k, v := range env {
		tmpLogger := c.cpanel.Logger.With(zap.String("envKey", k), zap.String("envValue", v))
		// setting the env
		tmpLogger.Debug("setting cpanel env")
		if err := os.Setenv(k, v); err != nil {
			c.cpanel.Logger.Error("failed to set cpanel env")
			return e.MakeErr(e.FAILED_TO_SET_CPANEL_ENV, err)
		}
	}

	// running command to get all cpanel users info
	tmpLogger := c.cpanel.Logger.With(zap.String("command", "whmapi1 listaccts --output=json"))
	tmpLogger.Info("getting all cpanel users info")
	output, _, err := helpers.ExecuteCommand(false, "whmapi1", "listaccts", "--output=json")
	if err != nil {
		tmpLogger.Error(err.Error())
		return err
	}

	var accounts AccountList
	var users []string

	// unmarshal whmapi json response
	if err := json.Unmarshal([]byte(output), &accounts); err != nil {
		tmpLogger.Error(err.Error())
		return e.MakeErr(e.UNMARSHAL_ERR, err)
	}

	// looping through the cpanel response to set the cpanel users
	for _, acct := range accounts.Data.Acct {
		helpers.ColorPrint(fmt.Sprintf("new user has been detected: %s\n", acct.User), "green")
		tmpLogger.Info("new user has been detected", zap.String("cpanelUser", acct.User))
		users = append(users, acct.User)
	}

	// set the cpanel users
	tmpLogger.Info(fmt.Sprintf("%d cpanel users has been found", len(users)), zap.String("cpanelUsers", fmt.Sprintf("[ %s ]", strings.Join(users, ", "))))
	c.cpanel.Users = users

	return nil
}

// SetLogFiles - find and set the access log files path for each cpanel user
// Return: [error in case an error occurred]
func (c *cpClient) SetLogFiles() error {
	// iterating trough the cpanel users
	c.cpanel.Logger.Info("finding cpanel users log files")
	for _, user := range c.cpanel.Users {
		// the log folder path
		logsFolder := fmt.Sprintf("/home/%s/access-logs", user)
		tmpLogger := c.cpanel.Logger.With(zap.String("logFolder", logsFolder), zap.String("cpanelUser", user))

		// get all the text files from the access logs folder of the user
		tmpLogger.Debug("searching log files")
		logFiles, err := helpers.FindTextFiles(logsFolder)
		if err != nil {
			tmpLogger.Error(err.Error())
			return err
		}

		// add the log files to the cpanel logs files
		tmpLogger.Debug(fmt.Sprintf("%d log files have been found", len(logFiles)), zap.String("logFiles", fmt.Sprintf("[\x20%s\x20]", strings.Join(logFiles, ",\x20"))))
		c.logFiles = append(c.logFiles, logFiles...)
	}

	return nil
}

// SortAndUnifyLogs - sort unify and reformat the cpanel log files and create one ip file to check based on the cpanel log files
// Return: [string - new ipFile to check,error in case an error occurred]
func (c *cpClient) SortAndUnifyLogs() (string, error) {
	// path to the desired ip file output
	ipFile := "/tmp/.ip.txt"
	tmpFille := "/tmp/.ip.tmp.txt"

	// iterating trough the cpanel log files
	for _, f := range c.logFiles {
		// command to reformat,sort,uniq the output of the cpanel log files
		cmd := fmt.Sprintf("cat %s | cut -d ' ' -f 1 | sort -n | uniq >> %s", f, tmpFille)
		tmpLogger := c.cpanel.Logger.With(zap.String("command", cmd))
		helpers.ColorPrint(fmt.Sprintf("parsing access log file: %s\n", f), "green")

		// running the command to create one ip file
		tmpLogger.Info("parsing cpanel user log file", zap.String("cpanelLogFile", f))
		if _, _, err := helpers.ExecuteCommand(false, cmd); err != nil {
			tmpLogger.Error(err.Error())
			return "", err
		}
	}

	defer func() {
		// delete tempFile on finish
		c.cpanel.Logger.Debug(fmt.Sprintf("deleting the file: %s", tmpFille))
		os.Remove(tmpFille)
	}()

	// command to reformat,sort,uniq the output of the cpanel log files
	cmd := fmt.Sprintf("cat %s | sort -n | uniq > %s", tmpFille, ipFile)
	tmpLogger := c.cpanel.Logger.With(zap.String("command", cmd))

	// running the command to create one ip file
	tmpLogger.Info("creating new ip file based on the cpanel log files", zap.String("cpanelLogFiles", fmt.Sprintf("[\x20%s\x20]", strings.Join(c.logFiles, ",\x20"))))
	if _, _, err := helpers.ExecuteCommand(false, cmd); err != nil {
		tmpLogger.Error(err.Error())
		return "", err
	}

	// validating the desired ip has been created successfully
	tmpLogger.Debug(fmt.Sprintf("validating the new ip file(%s) has been crated base on cpanel log files", ipFile))
	if !helpers.IsExist(ipFile, true) {
		tmpLogger.Error(e.CPANEL_IP_FILE_NOT_FOUND)
		return "", e.MakeErr(e.CPANEL_IP_FILE_NOT_FOUND, nil)
	}

	tmpLogger.Info(fmt.Sprintf("cpanel ip file has been created successfully - %s", ipFile))
	return ipFile, nil
}
