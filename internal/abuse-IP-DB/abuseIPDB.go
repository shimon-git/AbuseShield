package abuseipdb

import (
	"context"
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
	Ipv6          bool
	Ipv4          bool
	Enable        bool     `yaml:"enable"`
	Limit         int      `yaml:"limit"`
	Interval      int      `yaml:"interval"`
	BlackListFile string   `yaml:"blacklist_file"`
	WhiteListFile string   `yaml:"whitelist_file"`
	ApiKeys       []string `yaml:"api_keys"`
	Score         int      `yaml:"score"`
	BlockTor      bool     `yaml:"blockTor"`
	Exclude       struct {
		Domains  []string `yaml:"domains"`
		Networks []string `yaml:"networks"`
		Crawlers bool     `yaml:"crawlers"`
	} `yaml:"exclude"`
}

type abuseIPDBClient struct {
	abuseIPDB                  AbuseIPDB
	maxIPChecks                int
	client                     *http.Client
	currentAPIKey              string
	currentAPIKeyRequestsLimit int
	validAPIKeys               map[string]int
	mu                         sync.Mutex
	limit                      struct {
		enable      bool
		limitNumber int
	}
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
	availableRequestsNumber int // Keep or adjust this field as needed
}
type abuseIPDBErrResponse struct {
	Errors []struct {
		Detail string `json:"detail"`
	} `json:"errors"`
}

// New - create a new abuseipdb client
// Args: [AbuseIPDB configuration]
// Returns a pointer to abuseipdb client
func New(a AbuseIPDB, validation bool) (*abuseIPDBClient, error) {
	// create new variable for abuseipdb client
	var abuseIPDBclient abuseIPDBClient

	// set the abuseipdb configurations
	abuseIPDBclient.abuseIPDB = a
	// setting max ip checks that can be check against the abuseipdb API server
	err := abuseIPDBclient.SetMaxIPCHecks(validation)

	// set limit ips to check
	if a.Limit > 0 {
		abuseIPDBclient.limit.enable = true
		abuseIPDBclient.limit.limitNumber = a.Limit
	}

	// return a reference to abuseipdb and error if ocurred
	return &abuseIPDBclient, err
}

// setNewKey - set new http client fot abuseipdb API requests with the provided API key
// Args: [API key for abuseipdb API requests]
func (a *abuseIPDBClient) setNewKey(apiKey string) {
	// create new http client with custom headers
	httpClient := helpers.HttpClient{
		Headers: map[string]string{
			"Accept": "application/json",
			"Key":    apiKey,
		},
	}
	// set the current API key
	a.currentAPIKey = apiKey
	// set the abuseipdb client
	a.client = httpClient.NewHttpClient()
}

// SetMaxIPCHecks - set maximum available API requests to abuseipdb
func (a *abuseIPDBClient) SetMaxIPCHecks(validation bool) error {
	if validation {
		// print info message to the user
		helpers.ColorPrint("[+] validating API keys for abuseipdb.com....", "green")
	}
	// create a map[api-key]available-API-requests - the map will contain only valid api keys that
	validApiKeys := make(map[string]int)
	// generate dummy ip to check against th abuseipdb
	ip := helpers.GenerateDummyIP()
	// initialize a counter for the available API requests
	availableApiRequests := 0
	// iterate over the provided API keys
	for _, key := range a.abuseIPDB.ApiKeys {
		// set a new key
		a.setNewKey(key)
		// get data of dummy ip to check available api request for the current api key iteration
		data, err := a.getIPData(ip, true)
		if err != nil && !strings.Contains(err.Error(), e.DAILY_RATE_LIMIT_EXCEEDED_ABUSEIPDB) {
			return err
		}
		// check if api key have more then 0 available api requests
		if data.availableRequestsNumber > 0 {
			if validation {
				// print information to the console
				message := fmt.Sprintf("[+] API key is valid, available requests: %d  - %s", data.availableRequestsNumber, key)
				helpers.ColorPrint(message, "green")
			}
			// add the api key to the valid api keys map
			validApiKeys[key] = data.availableRequestsNumber
		} else if validation {
			// in case api key is valid but daily api requests exceeded print it to console
			message := fmt.Sprintf("[+] API key cannot be used because daily rate limit exceeded - %s", key)
			helpers.ColorPrint(message, "red")
		}
		// add the available api requests number
		availableApiRequests += data.availableRequestsNumber
	}
	// set the abuseipdb client valid api keys
	a.validAPIKeys = validApiKeys
	// set the max ip checks number
	a.maxIPChecks = availableApiRequests
	// return nil error
	return nil
}

func (a *abuseIPDBClient) getIPData(ip string, apiKeysValidation bool) (abuseIPDBResponse, error) {
	// lock the function to run it synchronously for avoiding interval issues
	a.mu.Lock()
	defer a.mu.Unlock()

	var response abuseIPDBResponse
	var errResponse abuseIPDBErrResponse

	params := url.Values{}
	params.Add("ipAddress", ip)
	params.Add("maxAgeInDays", "90")
	params.Add("verbose", "")
	url := "https://api.abuseipdb.com/api/v2/check" + "?" + params.Encode()

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
		if strings.Contains(string(body), e.DAILY_RATE_LIMIT_EXCEEDED_ABUSEIPDB) && !apiKeysValidation {
			a.currentAPIKeyRequestsLimit = 0
			if err := a.getNewKey(); err != nil {
				return response, err
			}
			a.setNewKey(a.currentAPIKey)
			return a.getIPData(ip, false)
		}
		if err := json.Unmarshal(body, &errResponse); err != nil {
			return response, e.MakeErr(fmt.Sprintf("%s \n%s, status code:%d while excepted status code is: %d, Body: %s, Current ip: %s", e.UNMARSHAL_ERR, e.INVALID_RESPONSE_CODE, res.StatusCode, http.StatusOK, string(body), ip), err)
		}
		return response, e.MakeErr(fmt.Sprintf("%s, status code:%d while excepted status code is: %d, error massage: %s, Current ip: %s", e.INVALID_RESPONSE_CODE, res.StatusCode, http.StatusOK, errResponse.Errors[0].Detail, ip), nil)
	}

	remainingChecksStr := res.Header.Get("X-Ratelimit-Remaining")

	if remainingChecksStr == "" {
		return response, e.MakeErr(fmt.Sprintf("%s, api-key: %s", e.EMPTY_REMAINING_CHECKS_HEADER, a.currentAPIKey), nil)
	}

	remainingChecks, err := strconv.Atoi(remainingChecksStr)
	if err != nil {
		return response, e.MakeErr(nil, err)
	}
	response.availableRequestsNumber = remainingChecks

	if err := json.Unmarshal(body, &response); err != nil {
		log.Fatalf("Failed to parse JSON: %s", err)
	}

	// api requests interval
	time.Sleep(time.Second * time.Duration(a.abuseIPDB.Interval))

	return response, nil

}

func (a *abuseIPDBClient) getNewKey() error {
	if a.currentAPIKeyRequestsLimit > 0 {
		return nil
	}
	a.validAPIKeys[a.currentAPIKey] = 0
	for k, v := range a.validAPIKeys {
		if v > 0 {
			a.currentAPIKeyRequestsLimit = v
			a.setNewKey(k)
			return nil
		}
	}
	return e.MakeErr(e.API_KEYS_LIMIT_HAS_BEEN_REACHED, nil)
}

func (a *abuseIPDBClient) CheckIPScore(cancelFunc context.CancelFunc, dataChan chan string, blacklistWriterChan chan string, whitelistWriterChan chan string, errChan chan string, goRoutineNumber *int, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() { *goRoutineNumber-- }()

	for ip := range dataChan {
		if a.limit.limitNumber <= 0 {
			cancelFunc()
			return
		}

		formattedIP, err := helpers.FormatIP(ip)
		if err != nil {
			errChan <- err.Error()
			// Move to the next IP if there's an error in formatting
			helpers.ColorPrint(fmt.Sprintf("[+] Error ocurred while trying to format the ip: %s\n %s", ip, err.Error()), "error")
			continue
		}

		if len(a.abuseIPDB.Exclude.Networks) > 0 && helpers.IsNetworkExclude(formattedIP, a.abuseIPDB.Exclude.Networks) {
			message := fmt.Sprintf("[+] Excluded IP: %s - This IP is within the exclusion ranges and has been added to the whitelist.", formattedIP)
			helpers.ColorPrint(message, "exclude")
			whitelistWriterChan <- ip
			continue
		}

		// Retrieve IP data
		ipData, err := a.getIPData(formattedIP, false)
		a.currentAPIKeyRequestsLimit = ipData.availableRequestsNumber
		if a.limit.enable {
			a.limit.limitNumber--
		}

		if err != nil && strings.Contains(err.Error(), e.API_KEYS_LIMIT_HAS_BEEN_REACHED) {
			errChan <- err.Error()
			cancelFunc()
			return
		}

		if err != nil {
			errChan <- err.Error()
			// Move to the next IP if there's an error in getting IP data
			helpers.ColorPrint(fmt.Sprintf("[+] Error ocurred while trying to check the ip: %s", ip), "error")
			continue
		}

		if a.abuseIPDB.Exclude.Crawlers && strings.Contains(strings.ToLower(ipData.Data.UsageType), "search engine") {
			message := fmt.Sprintf("[+] Whitelisted crawler IP: %s - domain: %s - country: %s - Identified as a crawler and successfully added to the whitelist.", ip, ipData.Data.Domain, ipData.Data.CountryCode)
			helpers.ColorPrint(message, "exclude")
			whitelistWriterChan <- ip
			continue
		}

		if len(a.abuseIPDB.Exclude.Domains) > 0 && helpers.IsDomainExclude(ipData.Data.Domain, a.abuseIPDB.Exclude.Domains) {
			message := fmt.Sprintf("[+] Whitelisted: IP %s (domain: %s) - county: %s - Successfully added to the whitelist due the domain exclusions.", ip, ipData.Data.Domain, ipData.Data.CountryCode)
			helpers.ColorPrint(message, "exclude")
			whitelistWriterChan <- ip
			continue
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
