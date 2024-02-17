package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	abuseipdb "github.com/shimon-git/AbuseShield/internal/abuse-IP-DB"
	"github.com/shimon-git/AbuseShield/internal/config"
	"github.com/shimon-git/AbuseShield/internal/cpanel"
	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
	"github.com/shimon-git/AbuseShield/internal/logger"
	"go.uber.org/zap"
)

var (
	errWg sync.WaitGroup
)

func main() {
	// print the abuse shield header
	helpers.PrintHeader("abuse-shield")
	// get app configurations
	conf := config.GetConfig()

	// initializing a new logger object
	logger, err := logger.New(conf.Logs)
	if err != nil {
		log.Panicf("Cannot create or write to log file - %s", err.Error())
	}
	defer logger.Sync()
	logger.Info("staring abuse shield checks")

	// check if cpanel module if cpanel module is enabled
	if conf.Cpanel.Enable {
		// print the cpanel header
		helpers.PrintHeader("cpanel")
		logger.Info("checking cpanel abuse")
		// set cpanel logger
		conf.Cpanel.Logger = logger
		// get ip file to check
		ipFile, err := cpanelAbuseChecker(conf.Cpanel)
		if err != nil {
			conf.Cpanel.Logger.Error(err.Error())
			log.Fatal(err)
		}
		// add the ip file to ip files checks
		logger.Debug("adding cpanel access logs to ip files checks slice")
		conf.Global.IPsFiles = append(conf.Global.IPsFiles, ipFile)
	}

	// abuseDBIP checker
	if conf.AbuseIPDB.Enable {
		// print the abuseipdb header
		helpers.PrintHeader("abuseipdb")
		// set abuseipdb logger
		conf.AbuseIPDB.Logger = logger
		logger.Info("using abuseipdb to check ips score")
		// call abuseipdb checker to check for abuse
		if err := abuseIPDBChecker(conf.AbuseIPDB, conf.Global.IPsFiles, conf.Global.MaxThreads); err != nil {
			conf.AbuseIPDB.Logger.Error(err.Error())
			log.Fatal(err)
		}
	}
}

// cpanelAbuseChecker consolidates cPanel access logs into a single file for abuse detection.
// Args: [cp: cPanel configuration details, ipFileOutput: Destination for consolidated logs]
// Returns [string - ip file path, error - in case of error ocurred]
func cpanelAbuseChecker(cp cpanel.Cpanel) (string, error) {
	//initialize new cpanel client
	cp.Logger.Debug("initializing new cpanel client")
	cpanelClient := cpanel.New(cp, false)
	// if configured, set up to check all cPanel users
	if cp.CheckAllUsers {
		cp.Logger.Info("setting all cpanel users to check")
		if err := cpanelClient.SetAllUsers(); err != nil {
			return "", err
		}
	}
	// set up and find all user access logs
	cp.Logger.Info("setting up cpanel ips to check")
	if err := cpanelClient.SetLogFiles(); err != nil {
		return "", err
	}
	// sort and unify access logs, returning the path of the result file
	cp.Logger.Info("sorting and unifying cpanel ip file")
	accessLogsIPsFile, err := cpanelClient.SortAndUnifyLogs()
	if err != nil {
		return "", err
	}
	// return the path of the result file and nil error
	return accessLogsIPsFile, nil
}

// abuseIPDBChecker evaluates IPs against abuseipdb, segregating them into 'whitelist' and 'blacklist' files.
// Args: [abuseIPDB: Abuseipdb configurations, ipFiles: Paths to files with IPs for checking, maxThreads: number of max concurrence goroutines]
// Returns an error if the checking process encounters issues.
func abuseIPDBChecker(abuseIPDB abuseipdb.AbuseIPDB, ipFiles []string, maxThreads int) error {
	var wgAbuseIPDB sync.WaitGroup
	var wgWriter sync.WaitGroup
	var writerErr *e.SharedError

	// set the ips number to check
	abuseIPDB.Logger.Info("setting ips checker limit")
	if abuseIPDB.Limit == 0 {
		ipsNum, err := helpers.FilesLinesCounter(ipFiles)
		if err != nil {
			return err
		}
		abuseIPDB.Limit = ipsNum
	}
	abuseIPDB.Logger.Info(fmt.Sprintf("ips checker limit is: %d", abuseIPDB.Limit))

	// initialize a shared error object for handling errors in writer goroutines
	writerErr = e.NewSharedError()

	// create a new client for interacting with the abuseipdb API
	abuseIPDB.Logger.Debug("creating new abuseipdb client")
	abuseIPDBClient, err := abuseipdb.New(abuseIPDB, false)
	if err != nil {
		return err
	}

	// create context to pass the goroutines
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// set up channels for IP categorization
	blacklistWriterChan := make(chan string, 50)
	whitelistWriterChan := make(chan string, 50)

	// launch writer goroutines for handling output
	abuseIPDB.Logger.Info("creating blacklist file writer", zap.String("blacklistFilePath", abuseIPDB.BlackListFile))
	abuseIPDB.Logger.Info("creating whitelist file writer", zap.String("whitelistFilePath", abuseIPDB.WhiteListFile))
	wgWriter.Add(2)
	go helpers.FileWriter(abuseIPDB.BlackListFile, blacklistWriterChan, &wgWriter, writerErr)
	go helpers.FileWriter(abuseIPDB.WhiteListFile, whitelistWriterChan, &wgWriter, writerErr)

	// counter for managing the number of concurrent goroutines
	abuseIPDB.Logger.Debug("initializing goRoutinesCounter and dataChannels slice")
	goRoutinesCounter := 0
	dataChannels := []chan string{}

	// iterate over the provided IP files
	abuseIPDB.Logger.Info("parsing ip files", zap.String("ipFiles", strings.Join(ipFiles, ",\n")))
	for _, file := range ipFiles {
		tmpLogger := abuseIPDB.Logger.With(zap.Int("goRoutinesCounter", goRoutinesCounter), zap.Int("maxThreads", maxThreads), zap.String("ipFile", file))
		// throttle goroutine creation if max limit is reached
		for goRoutinesCounter >= maxThreads {
			tmpLogger.Debug("sleeping for 5 seconds due to maxThreads has been exceeded for ip file reader and abuseipdb checker")
			time.Sleep(time.Second * 5)
		}
		goRoutinesCounter++
		tmpLogger.Debug("adding go routine work for ip file reader abuseipdb checker", zap.Int("goRoutinesCounter", goRoutinesCounter))
		wgAbuseIPDB.Add(1)

		// set up a new channel for each file and start reading IPs
		tmpLogger.Debug("adding new channel to dataChannels slice for abuseipdb")
		dataChannels = append(dataChannels, make(chan string, 50))
		tmpLogger.Info("reading ip file")
		go helpers.FileReader(ctx, file, dataChannels[len(dataChannels)-1])

		// start a goroutine for checking IP scores against abuseipdb
		tmpLogger.Info("checking ips score")
		go abuseIPDBClient.CheckIPScore(cancel, dataChannels[len(dataChannels)-1], blacklistWriterChan, whitelistWriterChan, &goRoutinesCounter, &wgAbuseIPDB)
	}

	// wait for all IP checking goroutines to complete
	abuseIPDB.Logger.Debug("waiting for abuseipdb file readers goroutines to finish")
	wgAbuseIPDB.Wait()

	// close all writer channels after use
	abuseIPDB.Logger.Debug("closing blacklist and whitelist channels")
	close(blacklistWriterChan)
	close(whitelistWriterChan)

	// wait for all writer goroutines to finish
	abuseIPDB.Logger.Debug("waiting for abuseipdb file writers goroutines to finish")
	wgWriter.Wait()

	// check and return any errors that occurred during writing.
	return writerErr.GetError()
}
