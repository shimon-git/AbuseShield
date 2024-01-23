package helpers

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	e "github.com/shimon-git/AbuseShield/internal/errors"
)

func IPFileReader(ipFile string, dataChannel chan string) {
	readFile, err := os.Open(ipFile)
	if err != nil {
		log.Fatal(e.MakeErr(fmt.Sprintf("%s: %s\n", e.FILE_SCANNER_ERR, ipFile), err))
	}

	fileScanner := bufio.NewScanner(readFile)

	for fileScanner.Scan() {
		dataChannel <- fileScanner.Text()
	}

	if err := fileScanner.Err(); err != nil {
		log.Fatal(e.MakeErr(fmt.Sprintf("%s: %s\n", e.FILE_SCANNER_ERR, ipFile), err))
	}

	defer readFile.Close()
	close(dataChannel)
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

type BasicAuth struct {
	User     string
	Password string
}

type HttpClient struct {
	Headers map[string]string
	Auth    BasicAuth
}

func (h *HttpClient) NewHttpClient() *http.Client {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: h,
	}
	return client
}

func (h *HttpClient) RoundTrip(req *http.Request) (*http.Response, error) {
	if h.Headers != nil {
		for k, v := range h.Headers {
			req.Header.Add(k, v)
		}
	}

	if h.Auth.User != "" || h.Auth.Password != "" {
		req.SetBasicAuth(h.Auth.User, h.Auth.Password)
	}

	return http.DefaultTransport.RoundTrip(req)
}

func UniqSlice(slice []string) []string {
	uniqMap := make(map[string]bool)
	result := make([]string, 0, len(slice))

	for _, v := range slice {
		if !uniqMap[v] {
			uniqMap[v] = true
			result = append(result, v)
		}
	}

	return result
}

func IsFileExist(f string) error {
	_, err := os.Stat(f)
	if err != nil {
		return e.MakeErr(fmt.Sprintf("%s: %s", e.RETRIEVE_FILE_INFO_ERR, f), err)
	}
	return nil
}
