package main

import (
	"log"
	"os"
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
	// Basic ANSI Color Codes
	Black   = "\033[30m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"

	// Bright Versions
	BrightBlack   = "\033[90m"
	BrightRed     = "\033[91m"
	BrightGreen   = "\033[92m"
	BrightYellow  = "\033[93m"
	BrightBlue    = "\033[94m"
	BrightMagenta = "\033[95m"
	BrightCyan    = "\033[96m"
	BrightWhite   = "\033[97m"

	// Background Colors
	BlackBackground   = "\033[40m"
	RedBackground     = "\033[41m"
	GreenBackground   = "\033[42m"
	YellowBackground  = "\033[43m"
	BlueBackground    = "\033[44m"
	MagentaBackground = "\033[45m"
	CyanBackground    = "\033[46m"
	WhiteBackground   = "\033[47m"

	// Reset
	Reset = "\033[0m"
)

var (
	ipFile = "/tmp/.ip.txt"
)

func main() {
	showANSIColors()
	// get app configurations
	conf := config.GetConfig()

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
			log.Fatal("\033[31m", err, "\033[0m")
		}
	}
}

func showANSIColors() {
	myFigure := figure.NewColorFigure("Abuse - Shield", "isometric1", "gray", true)
	myFigure.Print()
	myFigure = figure.NewColorFigure("Abuse - Shield", "isometric2", "gray", true)
	myFigure.Print()
	myFigure = figure.NewColorFigure("Abuse - Shield", "isometric3", "gray", true)
	myFigure.Print()
	myFigure = figure.NewColorFigure("Abuse - Shield", "isometric4", "gray", true)
	myFigure.Print()
	println(Black, "This is black text", Reset)
	println(Red, "This is red text", Reset)
	println(Green, "This is green text", Reset)
	println(Yellow, "This is yellow text", Reset)
	println(Blue, "This is blue text", Reset)
	println(Magenta, "This is magenta text", Reset)
	println(Cyan, "This is cyan text", Reset)
	println(White, "This is white text", Reset)

	println(BrightBlack, "This is bright black text", Reset)
	println(BrightRed, "This is bright red text", Reset)
	println(BrightGreen, "This is bright green text", Reset)
	println(BrightYellow, "This is bright yellow text", Reset)
	println(BrightBlue, "This is bright blue text", Reset)
	println(BrightMagenta, "This is bright magenta text", Reset)
	println(BrightCyan, "This is bright cyan text", Reset)
	println(BrightWhite, "This is bright white text", Reset)

	println(BlackBackground, "This has a black background", Reset)
	println(RedBackground, "This has a red background", Reset)
	println(GreenBackground, "This has a green background", Reset)
	println(YellowBackground, "This has a yellow background", Reset)
	println(BlueBackground, "This has a blue background", Reset)
	println(MagentaBackground, "This has a magenta background", Reset)
	println(CyanBackground, "This has a cyan background", Reset)
	println(WhiteBackground, "This has a white background", Reset)
	os.Exit(0)

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
	resultsWriterChan := make(chan string, 50)
	wgWriter.Add(2)
	go helpers.IPFileWriter(abuseIPDB.ResultsFile, true, resultsWriterChan, &wgWriter, writerErr)
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
		go abuseIPDBClient.CheckIPScore(dataChannels[len(dataChannels)-1], resultsWriterChan, errWriterChan, &goRoutinesCounter, &wgAbuseIPDB)
	}
	wgAbuseIPDB.Wait()
	helpers.SafeChannelClose(resultsWriterChan)
	helpers.SafeChannelClose(errWriterChan)
	wgWriter.Wait()
	if abuseIPDBErr.GetError() != nil {
		return abuseIPDBErr.GetError()
	}
	return writerErr.GetError()
}
