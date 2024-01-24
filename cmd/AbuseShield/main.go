package main

import (
	"log"
	"sync"
	"time"

	abuseipdb "github.com/shimon-git/AbuseShield/internal/abuse-IP-DB"
	"github.com/shimon-git/AbuseShield/internal/config"
	"github.com/shimon-git/AbuseShield/internal/cpanel"
	"github.com/shimon-git/AbuseShield/internal/helpers"
)

var (
	ipFile = "/tmp/.ip.txt"
)

func main() {
	conf := config.GetConfig()

	// cpanel
	if conf.Cpanel.Enable {
		err := cpanelAbuseChecker(conf.Cpanel, ipFile)
		if err != nil {
			log.Fatal(err)
		}
		conf.Global.IPsFiles = append(conf.Global.IPsFiles, ipFile)
	}

	if conf.AbuseIPDB.Enable {
		var wgAbuseIPDB sync.WaitGroup
		var wgWriter sync.WaitGroup
		var abuseIPDBErr error
		var writerErr error

		abuseIPDBClient, err := abuseipdb.New(conf.AbuseIPDB)
		if err != nil {
			log.Fatal(err)
		}
		maxGoRoutines := 10
		writerChan := make(chan string, 50)
		wgWriter.Add(1)
		go helpers.IPFileWriter(conf.AbuseIPDB.ResultsFile, true, writerChan, &wgWriter, &writerErr)
		for _, file := range conf.Global.IPsFiles {
			for {
				if maxGoRoutines > 0 {
					break
				}
				time.Sleep(time.Second * 5)
			}
			wgAbuseIPDB.Add(1)
			dataChan := make(chan string, 50)

			go helpers.IPFileReader(file, dataChan)
			go abuseIPDBClient.CheckIPScore(dataChan, writerChan, &wgWriter, &abuseIPDBErr)
		}
		wgAbuseIPDB.Wait()
		close(writerChan)
		wgWriter.Wait()
	}
}

func cpanelAbuseChecker(cp cpanel.Cpanel, ipFile string) error {
	cpanelClient := cpanel.New(cp)
	if cp.CheckAllUsers {
		// set cpanelClient users to check
		if err := cpanelClient.SetAllUsers(); err != nil {
			return err
		}
	}
	if err := cpanelClient.SetLogFiles(); err != nil {
		return err
	}
	if err := cpanelClient.SortAndUnifyLogs(ipFile); err != nil {
		return err
	}
	return nil
}
