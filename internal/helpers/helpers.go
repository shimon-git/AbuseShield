package helpers

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"

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

func GenerateDummyIP() string {
	// Create a new random number generator with a custom seed
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)

	// Generate random values for each octet
	octet1 := rand.Intn(224)
	octet2 := rand.Intn(256)
	octet3 := rand.Intn(256)
	octet4 := rand.Intn(256)

	return fmt.Sprintf("%d.%d.%d.%d", octet1, octet2, octet3, octet4)
}
