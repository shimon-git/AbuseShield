package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shimon-git/abuse_checker/internal/types"
)

func getUserData() types.UserData {
	var u types.UserData
	flag.StringVar(&u.IPFilePath, "ip-file", "", "Path to the IP file to check")
	flag.StringVar(&u.IPFilePath, "i", "", "Alias for --ip-file")

	flag.BoolVar(&u.CSF, "csf", false, "Enable CSF integration for automating blocking of malicious IPs")
	flag.BoolVar(&u.CSF, "c", false, "Alias for --csf")

	flag.StringVar(&u.APIKey, "api-key", "", "Set API key to use")
	flag.StringVar(&u.APIKey, "a", "", "Alias for --api-key")
	flag.Parse()

	// Check ip file path has been given
	if u.IPFilePath == "" {
		fmt.Printf("Usage: %s --ip-file [ip-file-to-check]\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	return u
}
