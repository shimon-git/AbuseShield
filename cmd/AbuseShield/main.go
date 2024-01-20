package main

import (
	"github.com/shimon-git/AbuseShield/internal/config"
	"github.com/shimon-git/AbuseShield/internal/sophos"
)

func main() {
	conf := config.GetConfig()
	if conf.Sophos.Enable {
		sc := sophos.New(conf.Sophos)
		sc.VerifyConnection()
	}
}
