package main

import (
	"fmt"
	"os"

	"github.com/shimon-git/abuse_checker/internal/helpers"
)

func main() {
	dataChannel := make(chan string)
	data := getUserData()
	err := helpers.IPFileProcessor(data, dataChannel)
	if err != nil {
		os.Exit(1)
	}
	for {
		x := <-dataChannel
		fmt.Println(x)
	}
}
