package helpers

import (
	"bufio"
	"fmt"
	"log"
	"os"

	e "github.com/shimon-git/abuse_checker/internal/errors"
	"github.com/shimon-git/abuse_checker/internal/types"
)

func IPFileProcessor(u types.UserData, dataChannel chan string) {
	readFile, err := os.Open(u.IPFilePath)
	if err != nil {
		log.Fatal(e.MakeErr(fmt.Sprintf("%s: %s\n", e.FILE_SCANNER_ERROR, u.IPFilePath), err))
	}

	fileScanner := bufio.NewScanner(readFile)

	for fileScanner.Scan() {
		dataChannel <- fmt.Sprintf("%s\n", fileScanner.Text())
	}

	close(dataChannel)

	if err := fileScanner.Err(); err != nil {
		log.Fatal(e.MakeErr(fmt.Sprintf("%s: %s\n", e.FILE_SCANNER_ERROR, u.IPFilePath), err))
	}

	defer readFile.Close()
}
