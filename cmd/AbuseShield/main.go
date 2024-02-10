package main

import (
	"context"
	"log"
	"sync"
	"time"

	abuseipdb "github.com/shimon-git/AbuseShield/internal/abuse-IP-DB"
	"github.com/shimon-git/AbuseShield/internal/config"
	"github.com/shimon-git/AbuseShield/internal/cpanel"
	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
	"github.com/shimon-git/AbuseShield/internal/logger"
)

var (
	errWg sync.WaitGroup
)

func main() {

	// print the abuse shield header
	helpers.PrintHeader("abuse-shield")
	// get app configurations
	conf := config.GetConfig()

	// create new logger
	l := logger.Log{
		Enable:     conf.Logs.Enable,
		Level:      conf.Logs.Level,
		MaxLogSize: conf.Logs.MaxLogSize,
		LogFile:    conf.Logs.LogFile,
	}
	logger, err := logger.New(l)
	if err != nil {
		log.Panicf("Cannot create or write to log file - %s", err.Error())
	}
	defer logger.Sync()

	// cpanel checker
	if conf.Cpanel.Enable {
		// print the cpanel header
		helpers.PrintHeader("cpanel")
		conf.Cpanel.Logger = logger
		ipFile, err := cpanelAbuseChecker(conf.Cpanel)
		if err != nil {
			log.Fatal(err)
		}
		conf.Global.IPsFiles = append(conf.Global.IPsFiles, ipFile)
	}

	// abuseDBIP checker
	if conf.AbuseIPDB.Enable {
		// print the abuseipdb header
		helpers.PrintHeader("abuseipdb")
		conf.AbuseIPDB.Logger = logger
		if err := abuseDBIPChecker(conf.AbuseIPDB, conf.Global.IPsFiles, conf.Global.MaxThreads); err != nil {
			log.Fatal(err)
		}
	}

}

// cpanelAbuseChecker consolidates cPanel access logs into a single file for abuse detection.
// Args: [cp: cPanel configuration details, ipFileOutput: Destination for consolidated logs]
// Returns [string - ip file path, error - in case of error ocurred]
func cpanelAbuseChecker(cp cpanel.Cpanel) (string, error) {
	//initialize new cpanel client
	cpanelClient := cpanel.New(cp)
	// if configured, set up to check all cPanel users
	if cp.CheckAllUsers {
		if err := cpanelClient.SetAllUsers(); err != nil {
			return "", err
		}
	}
	// set up and find all user access logs
	if err := cpanelClient.SetLogFiles(); err != nil {
		return "", err
	}
	// sort and unify access logs, returning the path of the result file
	accessLogsIPsFile, err := cpanelClient.SortAndUnifyLogs()
	if err != nil {
		return "", err
	}
	// return the path of the result file and nil error
	return accessLogsIPsFile, nil
}

// abuseDBIPChecker evaluates IPs against abuseipdb, segregating them into 'whitelist', 'blacklist', and 'error' files.
// Args: [abuseIPDB: Abuseipdb configurations, ipFiles: Paths to files with IPs for checking, errFile: Path for recording errors]
// Returns an error if the checking process encounters issues.
func abuseDBIPChecker(abuseIPDB abuseipdb.AbuseIPDB, ipFiles []string, maxThreads int) error {
	var wgAbuseIPDB sync.WaitGroup
	var wgWriter sync.WaitGroup

	// set the ips number to check
	if abuseIPDB.Limit == 0 {
		ipsNum, err := helpers.FilesLinesCounter(ipFiles)
		if err != nil {
			return err
		}
		abuseIPDB.Limit = ipsNum
	}

	// initialize a shared error object for handling errors in writer goroutines
	writerErr := e.NewSharedError()

	// create a new client for interacting with the abuseipdb API
	abuseIPDBClient, err := abuseipdb.New(abuseIPDB, false)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// set up channels for IP categorization
	blacklistWriterChan := make(chan string, 50)
	whitelistWriterChan := make(chan string, 50)

	// prepare to launch writer goroutines for handling output
	wgWriter.Add(2)
	go helpers.FileWriter(abuseIPDB.BlackListFile, blacklistWriterChan, &wgWriter, writerErr)
	go helpers.FileWriter(abuseIPDB.WhiteListFile, whitelistWriterChan, &wgWriter, writerErr)

	// counter for managing the number of concurrent goroutines
	goRoutinesCounter := 0
	dataChannels := []chan string{}

	// iterate over the provided IP files
	for _, file := range ipFiles {
		// throttle goroutine creation if max limit is reached
		for goRoutinesCounter >= maxThreads {
			time.Sleep(time.Second * 5)
		}
		goRoutinesCounter++
		wgAbuseIPDB.Add(1)

		// set up a new channel for each file and start reading IPs
		dataChannels = append(dataChannels, make(chan string, 50))
		go helpers.FileReader(ctx, file, dataChannels[len(dataChannels)-1])

		// start a goroutine for checking IP scores against abuseipdb
		go abuseIPDBClient.CheckIPScore(cancel, dataChannels[len(dataChannels)-1], blacklistWriterChan, whitelistWriterChan, &goRoutinesCounter, &wgAbuseIPDB)
	}

	// wait for all IP checking goroutines to complete
	wgAbuseIPDB.Wait()

	// close all writer channels after use
	close(blacklistWriterChan)
	close(whitelistWriterChan)

	// wait for all writer goroutines to finish
	wgWriter.Wait()

	// check and return any errors that occurred during writing.
	return writerErr.GetError()
}
