package csf

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	e "github.com/shimon-git/AbuseShield/internal/errors"
)

type CSF struct {
	Enable  bool   `yaml:"enable"`
	Ipv6    bool   `yaml:"ipv6"`
	Ipv4    bool   `yaml:"ipv4"`
	Backup  string `yaml:"backup"`
	CSFFile string `yaml:"csf_file"`
}

type csf struct {
	ipv6       bool
	ipv4       bool
	backupFile string
	CSFFile    string
}

func New(csfConf CSF) *csf {
	var c csf
	c.ipv4 = csfConf.Ipv4
	c.ipv6 = csfConf.Ipv6
	c.backupFile = csfConf.Backup
	c.CSFFile = csfConf.CSFFile

	return &c
}

func (c csf) CsfBackup() error {
	if err := os.Remove(c.backupFile); err != nil && !os.IsNotExist(err) {
		return e.MakeErr(fmt.Sprintf("%s: %s", e.REMOVE_FILE_ERR, c.backupFile), err)
	}
	csfDenyConf, err := os.Open(c.CSFFile)
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s", e.OPEN_FILE_ERR, c.CSFFile), err)
	}
	defer csfDenyConf.Close()

	csfDenyConfBackup, err := os.Create(c.backupFile)
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s", e.CREATE_FILE_ERR, c.backupFile), err)
	}
	defer csfDenyConfBackup.Close()

	s, err := io.Copy(csfDenyConfBackup, csfDenyConf)
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s, destination: %s", e.COPY_FILE_ERR, c.CSFFile, c.backupFile), err)
	}
	fmt.Println(c.backupFile)
	fmt.Println(s)
	return nil
}

func (c *csf) IsCsfServiceActive() error {
	serviceName := "csf.service"
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s", e.COMMAND_EXECUTE_ERR, cmd.String()), err)
	}
	serviceStatus := strings.TrimSpace(string(output))
	if serviceStatus != "active" {
		return e.MakeErr(fmt.Sprintf("%s: %s", e.INACTIVE_SERVICE, serviceName), nil)
	}
	return nil
}
