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
	"sync/atomic"
	"time"

	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
	"go.uber.org/zap"
)

// AbuseIPDB - store the configurations for the abuseipdb
type AbuseIPDB struct {
	Ipv6          bool     //IPv6 support
	Ipv4          bool     //IPv4 support
	Enable        bool     `yaml:"enable"`         //Enable/Disable AbuseIPDB module
	Limit         int      `yaml:"limit"`          //Limit IPs number to check
	Interval      int      `yaml:"interval"`       //Interval seconds number to waits between requests
	BlackListFile string   `yaml:"blacklist_file"` //Blacklist file path
	WhiteListFile string   `yaml:"whitelist_file"` //Whitelist file path
	ApiKeys       []string `yaml:"api_keys"`       //API keys to use
	Score         int      `yaml:"score"`          //Score to consider IP as malicious
	BlockTor      bool     `yaml:"blockTor"`       //Block tor IPs
	Exclude       struct {
		Domains  []string `yaml:"domains"`  //Exclude domains from check
		Networks []string `yaml:"networks"` //Exclude networks from check
		Crawlers bool     `yaml:"crawlers"` //Exclude crawlers from check
	} `yaml:"exclude"`
	Logger *zap.Logger
}

// abuseIPDBClient - struct to hold runtime abuseipdb configurations
type abuseIPDBClient struct {
	abuseIPDB                  AbuseIPDB      //AbuseIPDB configurations
	maxIPChecks                int            //Available API calls to check if IP is malicious
	client                     *http.Client   //HTTP client to send http requests to abuseipdb
	currentAPIKey              string         //Current API key in use
	currentAPIKeyRequestsLimit int            //Available API calls number for the current API key
	validAPIKeys               map[string]int //map that contains all the API keys and their available api calls number - [API-KEY]API-CALLS-NUMBER
	mu                         sync.Mutex     // mutex to keep functions synchronized
	limit                      struct {
		enable      bool  //Enable/Disable ip check limit
		limitNumber int32 //IP to check - limit number
	}
}

// abuseIPDBResponse - struct to store the abuseipdb http response
type abuseIPDBResponse struct {
	Data struct {
		Score       int    `json:"abuseConfidenceScore"` //IP score
		Tor         bool   `json:"isTor"`                //Is the IP belong to Tor
		CountryCode string `json:"countryCode"`          //IP country code
		Domain      string `json:"domain"`               //Domain that resolve to the IP
		IPAddress   string `json:"ipAddress"`            //IP address
		ISP         string `json:"isp"`                  //IP ISP provider
		UsageType   string `json:"usageType"`            //The usage type of the IP
	} `json:"data"`
	availableRequestsNumber int //Available API calls
}

// abuseIPDBErrResponse - struct to store the abuseipdb http error response
type abuseIPDBErrResponse struct {
	Errors []struct {
		Detail string `json:"detail"`
	} `json:"errors"`
}

// New - create new abuseipdb client
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
		abuseIPDBclient.limit.limitNumber = int32(a.Limit)
	}

	// return a reference to abuseipdb and error if occurred
	return &abuseIPDBclient, err
}

// setNewKey - set new http client fot abuseipdb API requests with the provided API key
// Args: [API key for abuseipdb API requests - string]
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
// Args: [validation bool - print validation progress]
// Return: [error - in case of error occurred]
func (a *abuseIPDBClient) SetMaxIPCHecks(validation bool) error {
	if validation {
		// print info message to the user
		helpers.ColorPrint("validating API keys for abuseipdb.com....\n", "green")
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
				message := fmt.Sprintf("API key is valid, available requests: %d  - %s\n", data.availableRequestsNumber, key)
				helpers.ColorPrint(message, "green")
			}
			// add the api key to the valid api keys map
			validApiKeys[key] = data.availableRequestsNumber
		} else if validation {
			// in case api key is valid but daily api requests exceeded print it to console
			message := fmt.Sprintf("API key cannot be used because daily rate limit exceeded - %s\n", key)
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

// getIPData - send http request to abuseipdb for checking IP
// Args: [ip: IP to check,apiKeysValidation: api validation key mode]
// Returns [abuseIPDBResponse: abuseipdb http response,error: in case of error occurred]
func (a *abuseIPDBClient) getIPData(ip string, apiKeysValidation bool) (abuseIPDBResponse, error) {
	// lock the function to run it synchronously for avoiding interval issues
	a.mu.Lock()
	defer a.mu.Unlock()

	var response abuseIPDBResponse
	var errResponse abuseIPDBErrResponse

	// set url params
	params := url.Values{}
	params.Add("ipAddress", ip)
	params.Add("maxAgeInDays", "90")
	params.Add("verbose", "")
	url := "https://api.abuseipdb.com/api/v2/check" + "?" + params.Encode()

	// send http Get request to abuseipdb
	res, err := a.client.Get(url)
	if err != nil {
		return response, e.MakeErr(e.HTTP_GET_ERR, err)
	}
	defer res.Body.Close()

	// read the response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return response, e.MakeErr(e.READ_RESPONSE_BODY_ERR, err)
	}

	// check if the response status code is ok(200)
	if res.StatusCode != http.StatusOK {
		// check if the error is because current API key exceeded the daily rate limit for API calls
		if strings.Contains(string(body), e.DAILY_RATE_LIMIT_EXCEEDED_ABUSEIPDB) && !apiKeysValidation {
			// set the api key available requests number
			a.currentAPIKeyRequestsLimit = 0
			// get new api key
			if err := a.getNewKey(); err != nil {
				return response, err
			}
			// call the current function again
			return a.getIPData(ip, false)
		}
		// extract the abuseipdb error
		if err := json.Unmarshal(body, &errResponse); err != nil {
			return response, e.MakeErr(fmt.Sprintf("%s \n%s, status code:%d while excepted status code is: %d, Body: %s, Current ip: %s", e.UNMARSHAL_ERR, e.INVALID_RESPONSE_CODE, res.StatusCode, http.StatusOK, string(body), ip), err)
		}
		// return empty response and the error
		return response, e.MakeErr(fmt.Sprintf("%s, status code:%d while excepted status code is: %d, error massage: %s, Current ip: %s", e.INVALID_RESPONSE_CODE, res.StatusCode, http.StatusOK, errResponse.Errors[0].Detail, ip), nil)
	}

	// set the remaining API calls based on the `X-Ratelimit-Remaining` header
	if err := a.setRemainingApiCalls(res.Header.Get("X-Ratelimit-Remaining"), &response); err != nil {
		return response, err
	}

	// unmarshal the http response body into the response variable
	if err := json.Unmarshal(body, &response); err != nil {
		log.Fatalf("Failed to parse JSON: %s", err)
	}

	//abuseipdb interval
	time.Sleep(time.Second * time.Duration(a.abuseIPDB.Interval))

	return response, nil
}

// setRemainingApiCalls - set the remaining api calls for the current abuseipdb client API key
// Args: [availableApiCalls: remaining api calls, a pointer to abuseipdb response]
func (a *abuseIPDBClient) setRemainingApiCalls(availableApiCalls string, res *abuseIPDBResponse) error {
	// check if the availableApiCalls variable is not empty
	if availableApiCalls == "" {
		return e.MakeErr(fmt.Sprintf("%s, api-key: %s", e.EMPTY_REMAINING_CHECKS_HEADER, a.currentAPIKey), nil)
	}

	// convert the availableApiCalls variable from string to int
	availableApiCallsInt, err := strconv.Atoi(availableApiCalls)
	if err != nil {
		return e.MakeErr(nil, err)
	}

	// set the available api requests number on the response and the abuseipdb client
	res.availableRequestsNumber = availableApiCallsInt
	a.currentAPIKeyRequestsLimit = availableApiCallsInt

	return nil
}

// getNewKey - iterating over the abuseipdb client api keys to find a new key
// Return: [error: in case of error occurred]
func (a *abuseIPDBClient) getNewKey() error {
	// check if the current api key don't have available api requests calls
	if a.currentAPIKeyRequestsLimit > 0 {
		return nil
	}
	// update the api key and the api calls number in the a.validAPIKeys map
	a.validAPIKeys[a.currentAPIKey] = 0

	// iterating through the api keys in the a.validAPIKeys(k:api-key, v: available api calls number)
	for k, v := range a.validAPIKeys {
		// check the available api calls number for the iterated key is over then 0
		if v > 0 {
			//set the remaining api calls number for the current api key
			a.currentAPIKeyRequestsLimit = v
			//set the api key
			a.setNewKey(k)
			return nil
		}
	}

	return e.MakeErr(e.API_KEYS_LIMIT_HAS_BEEN_REACHED, nil)
}

// CheckIPScore - check for malicious ips based on the ip score
// Args: [
// cancelFunc: context cancel function for canceling the execution,
// dataChan: channel to collect the ips to check,
// blacklistWriterChan: channel to write the malicious ips,
// whitelistWriterChan: channel to write the unmalicious ips,
// goRoutineNumber: update the goroutine number when execution finish,
// wg: waitgroup to sync with the caller function
// ]
// Note: CheckIPScore function designed to run as a goroutine
func (a *abuseIPDBClient) CheckIPScore(cancelFunc context.CancelFunc, dataChan chan string, blacklistWriterChan chan string, whitelistWriterChan chan string, goRoutineNumber *int, wg *sync.WaitGroup) {
	defer func() {
		*goRoutineNumber--
		wg.Done()
	}()

	// iterate over the IPs in the channel
	for ip := range dataChan {
		// check if limit ip checks number has exceeded
		if a.limit.enable && atomic.AddInt32(&a.limit.limitNumber, -1) < 0 {
			cancelFunc()
			return
		}
		// format the ip
		formattedIP, ipVersion, err := helpers.FormatIP(ip)
		if err != nil {
			a.abuseIPDB.processError(ip, err)
			continue
		}

		if (!a.abuseIPDB.Ipv4 && ipVersion == 4) || (!a.abuseIPDB.Ipv6 && ipVersion == 6) {
			fmt.Printf("Passing on Ip: %s - ipv%d is disable.\n", formattedIP, ipVersion)
			continue
		}

		// check if the ip should be excluded from the checks
		if len(a.abuseIPDB.Exclude.Networks) > 0 && helpers.IsNetworkExclude(formattedIP, a.abuseIPDB.Exclude.Networks) {
			r := abuseIPDBResponse{}
			r.Data.IPAddress = ip
			a.abuseIPDB.processIPClassification("networkExclusion", r, whitelistWriterChan)
			continue
		}

		// Retrieve IP data
		ipData, err := a.getIPData(formattedIP, false)
		if err != nil {
			a.abuseIPDB.processError(ip, err)
			// check if the error occurred because the api keys daily rate limit has been exceeded
			if strings.Contains(err.Error(), e.API_KEYS_LIMIT_HAS_BEEN_REACHED) {
				cancelFunc()
				return
			}
			continue
		}

		// check if crawlers has been exclude and the ip is in use by a crawler
		if a.abuseIPDB.Exclude.Crawlers && strings.Contains(strings.ToLower(ipData.Data.UsageType), "search engine") {
			a.abuseIPDB.processIPClassification("crawlersExclusion", ipData, whitelistWriterChan)
			continue
		}

		// check if the ip is assigned to domain that has been excluded
		if len(a.abuseIPDB.Exclude.Domains) > 0 && helpers.IsDomainExclude(ipData.Data.Domain, a.abuseIPDB.Exclude.Domains) {
			a.abuseIPDB.processIPClassification("domainExclusion", ipData, whitelistWriterChan)
			continue
		}

		// check ip score, send the malicious IPs to the blacklistWriterChan channel and the unmalicious IPs to the whitelistWriterChan channel
		if ipData.Data.Score >= a.abuseIPDB.Score {
			a.abuseIPDB.processIPClassification("malicious", ipData, blacklistWriterChan)
		} else {
			a.abuseIPDB.processIPClassification("unmalicious", ipData, whitelistWriterChan)
		}
	}
}

// processIPClassification - print the desired message based on the message type and passing the ip to the desired channel
// Args:[
// msgType: {`malicious`,`unmalicious`,`domainExclusion`,`crawlersExclusion`,`networkExclusion`},
// ipData: abuseipdb response,
// c: channel to pass the ip to
// ]
func (a AbuseIPDB) processIPClassification(msgType string, ipData abuseIPDBResponse, c chan string) {
	var message, messageType string
	switch msgType {
	case "malicious":
		message = fmt.Sprintf("malicious IP: { ip: %s - country: %s - domain: %s - ISP: %s - score: %d }\n", ipData.Data.IPAddress, ipData.Data.CountryCode, ipData.Data.Domain, ipData.Data.ISP, ipData.Data.Score)
		messageType = "red"
	case "unmalicious":
		message = fmt.Sprintf("unmalicious IP: { ip: %s - country: %s - domain: %s - ISP: %s - score: %d }\n", ipData.Data.IPAddress, ipData.Data.CountryCode, ipData.Data.Domain, ipData.Data.ISP, ipData.Data.Score)
		messageType = "green"
	case "domainExclusion":
		message = fmt.Sprintf("Whitelisted: IP %s (domain: %s) - county: %s - Successfully added to the whitelist due the domain exclusions.\n", ipData.Data.IPAddress, ipData.Data.Domain, ipData.Data.CountryCode)
		messageType = "exclude"
	case "crawlersExclusion":
		message = fmt.Sprintf("Whitelisted crawler IP: %s - domain: %s - country: %s - Identified as a crawler and successfully added to the whitelist.\n", ipData.Data.IPAddress, ipData.Data.Domain, ipData.Data.CountryCode)
		messageType = "exclude"
	case "networkExclusion":
		message = fmt.Sprintf("Excluded IP: %s - This IP is within the exclusion ranges and has been added to the whitelist.\n", ipData.Data.IPAddress)
		messageType = "exclude"
	default:
		message = "msgType must be one of the following options:[`malicious`,`unmalicious`,`domainExclusion`,`crawlersExclusion`,`networkExclusion`]"
		a.Logger.WithOptions(zap.AddCallerSkip(1)).Error(message)
		log.Fatal(message)
	}
	a.Logger.WithOptions(zap.AddCallerSkip(1)).Info(message)
	helpers.ColorPrint(message, messageType)
	c <- ipData.Data.IPAddress
}

// processError - print the error and pass the error to the desired channel
// Args: [
// ip: the ip that failed to check
// err: error that occurred
// ]
func (a AbuseIPDB) processError(ip string, err error) {
	errUserFormat := strings.Join(strings.Split(err.Error(), "-")[3:], "-")
	message := fmt.Sprintf("Error occurred while trying to check the ip: %s - %s", ip, errUserFormat)
	helpers.ColorPrint(message, "error")
	a.Logger.WithOptions(zap.AddCallerSkip(1)).Error(message)
}
