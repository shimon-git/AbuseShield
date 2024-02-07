package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/common-nighthawk/go-figure"
	abuseipdb "github.com/shimon-git/AbuseShield/internal/abuse-IP-DB"
	"github.com/shimon-git/AbuseShield/internal/config"
	"github.com/shimon-git/AbuseShield/internal/cpanel"
	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
)

var (
	errWg sync.WaitGroup
)

func main() {
	// print the abuse shield header
	printHeader("abuse-shield")

	//printHeader("csf")
	//printHeader("sophos")
	//os.Exit(0)

	// get app configurations
	conf := config.GetConfig()
	// setup channel for error logging
	errWriterChan := make(chan string, 50)
	writerErr := e.NewSharedError()
	go helpers.FileWriter(conf.Global.ErrorFile, false, errWriterChan, &errWg, writerErr)
	errWg.Add(1)
	defer func() {
		close(errWriterChan)
		errWg.Wait()
	}()

	// cpanel checker
	if conf.Cpanel.Enable {
		// print the cpanel header
		printHeader("cpanel")
		ipFile, err := cpanelAbuseChecker(conf.Cpanel)
		if err != nil {
			log.Fatal(err)
		}
		conf.Global.IPsFiles = append(conf.Global.IPsFiles, ipFile)
	}

	// abuseDBIP checker
	if conf.AbuseIPDB.Enable {
		// print the abuseipdb header
		printHeader("abuseipdb")
		if err := abuseDBIPChecker(conf.AbuseIPDB, conf.Global.IPsFiles, conf.Global.MaxThreads, errWriterChan); err != nil {
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
func abuseDBIPChecker(abuseIPDB abuseipdb.AbuseIPDB, ipFiles []string, maxThreads int, errChan chan string) error {
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
	go helpers.FileWriter(abuseIPDB.BlackListFile, true, blacklistWriterChan, &wgWriter, writerErr)
	go helpers.FileWriter(abuseIPDB.WhiteListFile, true, whitelistWriterChan, &wgWriter, writerErr)

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
		go abuseIPDBClient.CheckIPScore(cancel, dataChannels[len(dataChannels)-1], blacklistWriterChan, whitelistWriterChan, errChan, &goRoutinesCounter, &wgAbuseIPDB)
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

func printBanner(text string, color string, dashLen int) {
	myFigure := figure.NewColorFigure(strings.Repeat("-", dashLen), "", color, true)
	myFigure.Print()
	myFigure = figure.NewColorFigure(text, "", color, true)
	myFigure.Print()
	myFigure = figure.NewColorFigure(strings.Repeat("-", dashLen), "", color, true)
	myFigure.Print()
}

func printHeader(logo string) {
	switch logo {
	case "abuse-shield":
		// print abuse shield header
		printBanner("Abuse - Shield", "blue", 12)
	case "abuseipdb":
		// print abuseipdb header
		printBanner("AbuseIPDB", "gray", 9)
	case "cpanel":
		// print cpanel header
		printBanner("Cpanel", "cyan", 6)
	case "csf":
		// print csf header
		printBanner("CSF", "gray", 3)
	case "sophos":
		// print sophos header
		printBanner("Sophos", "yellow", 6)
	}
}
