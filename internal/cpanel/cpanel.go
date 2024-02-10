package cpanel

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
	"go.uber.org/zap"
)

const (
	ACCOUNT_NOT_EXIST_MESSAGE_PART = "Account does not exist."
)

type Cpanel struct {
	Enable        bool     `yaml:"enable"`
	Users         []string `yaml:"users"`
	CheckAllUsers bool     `yaml:"checkAllUsers"`
	Logger        *zap.Logger
}

type cpClient struct {
	cpanel   Cpanel
	logFiles []string
}

func New(c Cpanel) *cpClient {
	var cp cpClient
	cp.cpanel = c
	return &cp
}

func (c *cpClient) IsAllUsersExists() error {
	for _, user := range c.cpanel.Users {
		cmd := exec.Command("whmapi1", "accountsummary", fmt.Sprintf("user=%s", user))
		output, err := cmd.CombinedOutput()
		if err != nil {
			return e.MakeErr(fmt.Sprintf("%s: %s", e.COMMAND_EXECUTE_ERR, cmd.String()), err)
		}
		if strings.Contains(string(output), ACCOUNT_NOT_EXIST_MESSAGE_PART) {
			return e.MakeErr(fmt.Sprintf("%s: %s", e.CPANEL_USER_NOT_FOUND, user), nil)
		}
	}
	return nil
}

func (c *cpClient) IsCpanelInstalled() error {
	cmd := exec.Command("/usr/local/cpanel/cpanel")
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			if exitCode == 0 {
				return nil
			}
			return e.MakeErr(e.CPANEL_IN_NOT_INSTALLED, err)
		}
	}
	return nil
}

func (c *cpClient) SetAllUsers() error {
	env := map[string]string{
		"LC_ALL":   "",
		"LANG":     "en_US.UTF-8",
		"LANGUAGE": "en_US.UTF-8",
	}
	for k, v := range env {
		if err := os.Setenv(k, v); err != nil {
			return e.MakeErr(e.FAILED_TO_SET_CPANEL_ENV, err)
		}
	}
	cmd := exec.Command("sh", "-c", "whmapi1 listaccts --output=json | jq -r '.data.acct[].user'")
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return e.MakeErr(e.CPANEL_GET_USERS_LIST_ERR, err)
	}
	c.cpanel.Users = strings.Split(strings.TrimSpace(output.String()), "\n")
	return nil
}

func (c *cpClient) SetLogFiles() error {
	for _, user := range c.cpanel.Users {
		accessLogsDir := fmt.Sprintf("/home/%s/access-logs", user)
		files, err := os.ReadDir(accessLogsDir)
		if err != nil {
			return err
		}
		for _, file := range files {
			if !file.IsDir() {
				logFilePath := accessLogsDir + "/" + file.Name()
				isLogAsciiFile, err := isItAsciiFile(logFilePath)
				if err != nil {
					return err
				}
				if isLogAsciiFile {
					c.logFiles = append(c.logFiles, logFilePath)
				}
			}
		}
	}
	return nil
}

func isItAsciiFile(file string) (bool, error) {
	cmd := exec.Command("file", file)
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return false, e.MakeErr(fmt.Sprintf("%s, command: file %s", e.FILE_TYPE_CHECK_ERR, file), err)
	}
	return strings.Contains(output.String(), "ASCII text"), nil
}

func (c *cpClient) SortAndUnifyLogs() (string, error) {
	ipFile := "/tmp/.ip.txt"
	cmd := fmt.Sprintf("cat %s | cut -d ' ' -f 1 | sort -n | uniq > %s", strings.Join(c.logFiles, "\x20"), ipFile)
	if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
		return "", e.MakeErr(fmt.Sprintf("%s: %s", e.COMMAND_EXECUTE_ERR, cmd), err)
	}
	if !helpers.IsExist(ipFile, true) {
		return "", e.MakeErr(e.CPANEL_IP_FILE_NOT_FOUND, nil)
	}
	return ipFile, nil
}
