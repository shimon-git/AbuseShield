package main

import (
	"fmt"
	"log"

	"github.com/shimon-git/abuse_checker/internal/config"
	"github.com/shimon-git/abuse_checker/internal/helpers"
)

func main() {
	dataChannel := make(chan string, 5)
	data := getUserData()

	go helpers.IPFileProcessor(data, dataChannel)

	for ip := range dataChannel {
		fmt.Print(ip)
		//time.Sleep(time.Second * 2)
	}

	conf, err := config.ParseConfig(data.Config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(conf)

}
