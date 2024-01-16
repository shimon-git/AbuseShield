package abuseipdb

import "github.com/shimon-git/AbuseShield/internal/types"

// create a function  that get the channel and send requests to check the ip score

func Test(c chan string, x *types.T) {
	for i := range c {
		x.M = append(x.M, i)
	}
}
