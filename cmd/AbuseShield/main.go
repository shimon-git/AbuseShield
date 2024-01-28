package main

import (
	"log"
	"sync"
	"time"

	"github.com/common-nighthawk/go-figure"
	abuseipdb "github.com/shimon-git/AbuseShield/internal/abuse-IP-DB"
	"github.com/shimon-git/AbuseShield/internal/config"
	"github.com/shimon-git/AbuseShield/internal/cpanel"
	abuse_shield_errors "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
)

const (
	MAX_GO_ROUTINES = 10
)

var (
	ipFile = "/tmp/.ip.txt"
)

func main() {
	// get app configurations
	conf := config.GetConfig()

	// print abuse shield logo
	myFigure := figure.NewColorFigure("------------", "", "cyan", true)
	myFigure.Print()
	myFigure = figure.NewColorFigure("Abuse - Shield  ", "", "cyan", true)
	myFigure.Print()
	myFigure = figure.NewColorFigure("------------", "", "cyan", true)
	myFigure.Print()

	// cpanel checker
	if conf.Cpanel.Enable {
		err := cpanelAbuseChecker(conf.Cpanel, ipFile)
		if err != nil {
			log.Fatal(err)
		}
		conf.Global.IPsFiles = append(conf.Global.IPsFiles, ipFile)
	}

	// abuseDBIP checker
	if conf.AbuseIPDB.Enable {
		if err := abuseDBIPChecker(conf.AbuseIPDB, conf.Global.IPsFiles, conf.Global.ErrorFile); err != nil {
			log.Fatal(err)
		}
	}
}

func cpanelAbuseChecker(cp cpanel.Cpanel, ipFileOutput string) error {
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
	if err := cpanelClient.SortAndUnifyLogs(ipFileOutput); err != nil {
		return err
	}
	return nil
}

func abuseDBIPChecker(abuseIPDB abuseipdb.AbuseIPDB, ipFiles []string, errFile string) error {
	var wgAbuseIPDB sync.WaitGroup
	var wgWriter sync.WaitGroup
	abuseIPDBErr := abuse_shield_errors.NewSharedError()
	writerErr := abuse_shield_errors.NewSharedError()

	abuseIPDBClient, err := abuseipdb.New(abuseIPDB)
	if err != nil {
		return err
	}

	errWriterChan := make(chan string, 50)
	blacklistWriterChan := make(chan string, 50)
	whitelistWriterChan := make(chan string, 50)
	wgWriter.Add(3)
	go helpers.IPFileWriter(abuseIPDB.BlackListFile, true, blacklistWriterChan, &wgWriter, writerErr)
	go helpers.IPFileWriter(abuseIPDB.WhiteListFile, true, whitelistWriterChan, &wgWriter, writerErr)
	go helpers.IPFileWriter(errFile, true, errWriterChan, &wgWriter, writerErr)

	goRoutinesCounter := 0
	dataChannels := []chan string{}

	for _, file := range ipFiles {
		for {
			if goRoutinesCounter <= MAX_GO_ROUTINES {
				break
			}
			time.Sleep(time.Second * 5)
		}
		goRoutinesCounter++
		wgAbuseIPDB.Add(1)
		dataChannels = append(dataChannels, make(chan string, 50))

		go helpers.IPFileReader(file, dataChannels[len(dataChannels)-1])
		go abuseIPDBClient.CheckIPScore(dataChannels[len(dataChannels)-1], blacklistWriterChan, whitelistWriterChan, errWriterChan, &goRoutinesCounter, &wgAbuseIPDB)
	}
	wgAbuseIPDB.Wait()
	helpers.SafeChannelClose(blacklistWriterChan)
	helpers.SafeChannelClose(whitelistWriterChan)
	helpers.SafeChannelClose(errWriterChan)
	wgWriter.Wait()
	if abuseIPDBErr.GetError() != nil {
		return abuseIPDBErr.GetError()
	}
	return writerErr.GetError()
}
