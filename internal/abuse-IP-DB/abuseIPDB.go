package abuseipdb

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
)

type AbuseIPDB struct {
	Enable        bool     `yaml:"enable"`
	Limit         int      `yaml:"limit"`
	Interval      int      `yaml:"interval"`
	BlackListFile string   `yaml:"blacklist_file"`
	WhiteListFile string   `yaml:"whitelist_file"`
	ApiKeys       []string `yaml:"api_keys"`
	Score         int      `yaml:"score"`
	Ipv6          bool
	Ipv4          bool
}

type abuseIPDBClient struct {
	abuseIPDB                  AbuseIPDB
	maxIPChecks                int
	client                     *http.Client
	currentAPIKey              string
	currentAPIKeyRequestsLimit int
	validAPIKeys               map[string]int
	mu                         sync.Mutex
}

type abuseIPDBResponse struct {
	Data struct {
		Score       int    `json:"abuseConfidenceScore"`
		Tor         bool   `json:"isTor"`
		CountryCode string `json:"countryCode"`
		Domain      string `json:"domain"`
		IPAddress   string `json:"ipAddress"`
		ISP         string `json:"isp"`
		UsageType   string `json:"usageType"`
	} `json:"data"`
	limitRequestsNumber int // Keep or adjust this field as needed
}
type abuseIPDBErrResponse struct {
	Errors []struct {
		Detail string `json:"detail"`
	} `json:"errors"`
}

const (
	CONTENT_TYPE            = "application/json"
	ABUSE_DB_ENDPOINT       = "https://api.abuseipdb.com/api/v2/check"
	REMAINING_CHECKS_HEADER = "X-Ratelimit-Remaining"
)

func New(a AbuseIPDB) (*abuseIPDBClient, error) {
	var abuseDB abuseIPDBClient
	abuseDB.abuseIPDB = a
	err := abuseDB.SetMaxIPCHecks()
	return &abuseDB, err
}

func (a *abuseIPDBClient) setNewKey(apiKey string) {
	httpClient := helpers.HttpClient{
		Headers: map[string]string{
			"Accept": "application/json",
			"Key":    apiKey,
		},
	}
	a.currentAPIKey = apiKey
	a.client = httpClient.NewHttpClient()
}

func (a *abuseIPDBClient) SetMaxIPCHecks() error {
	helpers.ColorPrint("[+] validating API keys for abuseipdb.com....", "green")
	validApiKeys := make(map[string]int)
	ip := helpers.GenerateDummyIP()
	counter := 0
	for _, key := range a.abuseIPDB.ApiKeys {
		a.setNewKey(key)
		data, err := a.getIPData(ip)
		if err != nil {
			return err
		}
		if data.limitRequestsNumber > 0 {
			message := fmt.Sprintf("[+] API key is valid, available requests: %d  - %s", data.limitRequestsNumber, key)
			helpers.ColorPrint(message, "green")
			validApiKeys[key] = data.limitRequestsNumber
		} else {
			message := fmt.Sprintf("[+] API key cannot be used because daily rate limit exceeded - %s", key)
			helpers.ColorPrint(message, "red")
		}
		counter += data.limitRequestsNumber
	}
	a.validAPIKeys = validApiKeys
	a.maxIPChecks = counter
	return nil
}

func (a *abuseIPDBClient) getIPData(ip string) (abuseIPDBResponse, error) {
	// lock the function to run it synchronously for avoiding interval issues
	a.mu.Lock()
	defer a.mu.Unlock()

	var response abuseIPDBResponse
	var errResponse abuseIPDBErrResponse

	params := url.Values{}
	params.Add("ipAddress", ip)
	params.Add("maxAgeInDays", "90")
	params.Add("verbose", "")
	url := ABUSE_DB_ENDPOINT + "?" + params.Encode()

	res, err := a.client.Get(url)
	if err != nil {
		return response, e.MakeErr(e.HTTP_GET_ERR, err)
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return response, e.MakeErr(e.READ_RESPONSE_BODY_ERR, err)
	}

	if res.StatusCode != http.StatusOK {
		if err := json.Unmarshal(body, &errResponse); err != nil {
			return response, e.MakeErr(fmt.Sprintf("%s \n%s, status code:%d while excepted status code is: %d, Body: %s, Current ip: %s", e.UNMARSHAL_ERR, e.INVALID_RESPONSE_CODE, res.StatusCode, http.StatusOK, string(body), ip), err)
		}
		return response, e.MakeErr(fmt.Sprintf("%s, status code:%d while excepted status code is: %d, error massage: %s, Current ip: %s", e.INVALID_RESPONSE_CODE, res.StatusCode, http.StatusOK, errResponse.Errors[0].Detail, ip), nil)
	}

	remainingChecksStr := res.Header.Get(REMAINING_CHECKS_HEADER)

	if remainingChecksStr == "" {
		return response, e.MakeErr(fmt.Sprintf("%s, api-key: %s", e.EMPTY_REMAINING_CHECKS_HEADER, a.currentAPIKey), nil)
	}

	remainingChecks, err := strconv.Atoi(remainingChecksStr)
	if err != nil {
		return response, e.MakeErr(nil, err)
	}
	response.limitRequestsNumber = remainingChecks

	if err := json.Unmarshal(body, &response); err != nil {
		log.Fatalf("Failed to parse JSON: %s", err)
	}

	// api requests interval
	time.Sleep(time.Second * time.Duration(a.abuseIPDB.Interval))

	return response, nil

}

func (a *abuseIPDBClient) getNewKey() error {
	if a.currentAPIKeyRequestsLimit > 0 {
		time.Sleep(time.Second * 2)
		return nil
	}
	a.validAPIKeys[a.currentAPIKey] = 0
	for k, v := range a.validAPIKeys {
		if v > 0 {
			a.currentAPIKeyRequestsLimit = v
			a.setNewKey(k)
		}
	}
	return e.MakeErr(e.API_KEYS_LIMIT_HAS_BEEN_REACHED, nil)
}

func (a *abuseIPDBClient) CheckIPScore(dataChan chan string, blacklistWriterChan chan string, whitelistWriterChan chan string, errChan chan string, goRoutineNumber *int, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() { *goRoutineNumber-- }()

	for ip := range dataChan {
		formattedIP, err := helpers.FormatIP(ip)
		if err != nil {
			errChan <- err.Error()
			// Move to the next IP if there's an error in formatting
			continue
		}
		// Retrieve IP data
		ipData, err := a.getIPData(formattedIP)
		if err != nil {
			if strings.Contains(err.Error(), e.DAILY_RATE_LIMIT_EXCEEDED_ABUSEIPDB) {
				if err := a.getNewKey(); err != nil {
					errChan <- err.Error()
					return
				}
				a.setNewKey(a.currentAPIKey)
				ipData, err = a.getIPData(formattedIP)
			}
			if err != nil {
				errChan <- err.Error()
				// Move to the next IP if there's an error in getting IP data
				helpers.ColorPrint(fmt.Sprintf("[+] Error ocurred while trying to check the ip: %s", ip), "error")
				continue
			}
		}

		// if the ip score is bigger then or equal to the minimum ip score then send it the writerChan channel
		if ipData.Data.Score >= a.abuseIPDB.Score {
			message := fmt.Sprintf("[+] malicious IP: { ip: %s - country: %s - domain: %s - ISP: %s - score: %d }", ipData.Data.IPAddress, ipData.Data.CountryCode, ipData.Data.Domain, ipData.Data.ISP, ipData.Data.Score)
			helpers.ColorPrint(message, "red")
			blacklistWriterChan <- ip
		} else {
			message := fmt.Sprintf("[+] unmalicious IP: { ip: %s - country: %s - domain: %s - ISP: %s - score: %d }", ipData.Data.IPAddress, ipData.Data.CountryCode, ipData.Data.Domain, ipData.Data.ISP, ipData.Data.Score)
			helpers.ColorPrint(message, "green")
			whitelistWriterChan <- ip
		}
	}
}
