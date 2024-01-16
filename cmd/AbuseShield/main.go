package main

import (
	"fmt"
	"log"
	"sync"

	abuseipdb "github.com/shimon-git/AbuseShield/internal/abuse-IP-DB"
	"github.com/shimon-git/AbuseShield/internal/config"
	"github.com/shimon-git/AbuseShield/internal/helpers"
	"github.com/shimon-git/AbuseShield/internal/types"
)

var (
	wg   sync.WaitGroup
	conf types.Config
	err  error
	s    types.T
)

func main() {

	data := getUserData()
	if data.Config == "" {
		conf = types.Config{
			Global: types.GlobalConfigurations{
				IPsFiles: []string{data.IPFilePath},
			},
		}
	} else {
		conf, err = config.ParseConfig(data.Config)
		if err != nil {
			log.Fatal(err)
		}
	}

	// validate conf

	dataChannel := make(chan string)
	go abuseipdb.Test(dataChannel, &s)
	for i := 0; i < len(conf.Global.IPsFiles); i++ {
		go helpers.IPFileProcessor(conf.Global.IPsFiles[i], dataChannel, &wg)
	}
	wg.Add(len(conf.Global.IPsFiles))
	wg.Wait()
	close(dataChannel)
	fmt.Println(len(s.M))

}
