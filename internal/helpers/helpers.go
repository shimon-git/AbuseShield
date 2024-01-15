package helpers

import (
	"bufio"
	"fmt"
	"os"

	e "github.com/shimon-git/abuse_checker/internal/errors"
	"github.com/shimon-git/abuse_checker/internal/types"
)

func IPFileProcessor(u types.UserData, dataChannel chan string) error {
	readFile, err := os.Open(u.IPFilePath)
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s\n", e.OPEN_FILE_ERR, u.IPFilePath), err)
	}

	fileScanner := bufio.NewScanner(readFile)

	for fileScanner.Scan() {
		dataChannel <- fmt.Sprintf("%s\n", fileScanner.Text())
	}

	if err := fileScanner.Err(); err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s\n", e.FILE_SCANNER_ERROR, u.IPFilePath), err)
	}

	defer readFile.Close()

	return nil
}
