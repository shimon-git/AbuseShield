package abuseipdb

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
)

type AbuseIPDB struct {
	Enable      bool     `yaml:"enable"`
	Limit       int      `yaml:"limit"`
	Interval    int      `yaml:"interval"`
	ResultsFile string   `yaml:"results_file"`
	ApiKeys     []string `yaml:"api_keys"`
	Score       int      `yaml:"score"`
	Ipv6        bool
	Ipv4        bool
}

type abuseIPDBClient struct {
	abuseIPDB                  AbuseIPDB
	maxIPChecks                int
	client                     *http.Client
	currentAPIKey              string
	currentAPIKeyRequestsLimit int
	validAPIKeys               map[string]int
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
			validApiKeys[key] = data.limitRequestsNumber
		}
		counter += data.limitRequestsNumber
	}
	a.validAPIKeys = validApiKeys
	a.maxIPChecks = counter
	return nil
}

func (a *abuseIPDBClient) getIPData(ip string) (abuseIPDBResponse, error) {
	var responseObj abuseIPDBResponse

	params := url.Values{}
	params.Add("ipAddress", ip)
	params.Add("maxAgeInDays", "90")
	params.Add("verbose", "")
	url := ABUSE_DB_ENDPOINT + "?" + params.Encode()

	res, err := a.client.Get(url)
	if err != nil {
		return responseObj, e.MakeErr(e.HTTP_GET_ERR, err)
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return responseObj, e.MakeErr(e.READ_RESPONSE_BODY_ERR, err)
	}

	if res.StatusCode != http.StatusOK {
		return responseObj, e.MakeErr(fmt.Sprintf("%s, got:%d while excepted status code is: %d, Body: %s", e.INVALID_RESPONSE_CODE, res.StatusCode, http.StatusOK, string(body)), nil)
	}

	remainingChecksStr := res.Header.Get(REMAINING_CHECKS_HEADER)

	if remainingChecksStr == "" {
		return responseObj, e.MakeErr(fmt.Sprintf("%s, api-key: %s", e.EMPTY_REMAINING_CHECKS_HEADER, a.currentAPIKey), nil)
	}

	remainingChecks, err := strconv.Atoi(remainingChecksStr)
	if err != nil {
		return responseObj, e.MakeErr(nil, err)
	}
	responseObj.limitRequestsNumber = remainingChecks

	if err := json.Unmarshal(body, &responseObj); err != nil {
		log.Fatalf("Failed to parse JSON: %s", err)
	}

	return responseObj, nil

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

func (a *abuseIPDBClient) CheckIPScore(dataChan chan string, writerChan chan string, goRoutineNumber *int, wg *sync.WaitGroup, err *error) {
	for ip := range dataChan {
		ipData, e := a.getIPData(ip)
		if e != nil {
			*err = e
			wg.Done()
			break
		}

		if ipData.Data.Score >= a.abuseIPDB.Score {
			writerChan <- ip
		}
		// api requests interval
		time.Sleep(time.Second * time.Duration(a.abuseIPDB.Interval))
	}
	defer close(dataChan)
	wg.Done()
	*goRoutineNumber -=1
	}()
}
