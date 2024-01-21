package cpanel

import (
	"fmt"
	"os/exec"
	"strings"

	e "github.com/shimon-git/AbuseShield/internal/errors"
)

const (
	ACCOUNT_NOT_EXIST_MESSAGE_PART = "Account does not exist."
)

type Cpanel struct {
	Enable        bool     `yaml:"enable"`
	Users         []string `yaml:"users"`
	CheckAllUsers bool     `yaml:"checkAllUsers"`
}

type cpClient struct {
	cpanel Cpanel
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
