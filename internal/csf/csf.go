package csf

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	e "github.com/shimon-git/AbuseShield/internal/errors"
	"go.uber.org/zap"
)

type CSF struct {
	Enable  bool   `yaml:"enable"`
	Backup  string `yaml:"backup_file"`
	CSFFile string `yaml:"csf_file"`
	Ipv6    bool
	Ipv4    bool
	Logger  *zap.Logger
}

type csfClient struct {
	csf CSF
}

func New(csfConf CSF) *csfClient {
	var c csfClient
	c.csf = csfConf
	return &c
}

func (c csfClient) CsfBackup() error {
	if err := os.Remove(c.csf.Backup); err != nil && !os.IsNotExist(err) {
		return e.MakeErr(fmt.Sprintf("%s: %s", e.REMOVE_FILE_ERR, c.csf.Backup), err)
	}
	csfDenyConf, err := os.Open(c.csf.CSFFile)
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s", e.OPEN_FILE_ERR, c.csf.CSFFile), err)
	}
	defer csfDenyConf.Close()

	csfDenyConfBackup, err := os.Create(c.csf.Backup)
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s", e.CREATE_FILE_ERR, c.csf.Backup), err)
	}
	defer csfDenyConfBackup.Close()

	_, err = io.Copy(csfDenyConfBackup, csfDenyConf)
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s, destination: %s", e.COPY_FILE_ERR, c.csf.CSFFile, c.csf.Backup), err)
	}

	return nil
}

func (c *csfClient) IsCsfServiceActive() error {
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
