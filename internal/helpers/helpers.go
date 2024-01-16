package helpers

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sync"

	e "github.com/shimon-git/AbuseShield/internal/errors"
)

func IPFileProcessor(ipFile string, dataChannel chan string, wg *sync.WaitGroup) {
	readFile, err := os.Open(ipFile)
	if err != nil {
		log.Fatal(e.MakeErr(fmt.Sprintf("%s: %s\n", e.FILE_SCANNER_ERROR, ipFile), err))
	}

	fileScanner := bufio.NewScanner(readFile)

	for fileScanner.Scan() {
		dataChannel <- fmt.Sprintf("%s\n", fileScanner.Text())
	}

	if err := fileScanner.Err(); err != nil {
		log.Fatal(e.MakeErr(fmt.Sprintf("%s: %s\n", e.FILE_SCANNER_ERROR, ipFile), err))
	}

	defer readFile.Close()
	wg.Done()
}
