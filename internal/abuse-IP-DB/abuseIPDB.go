package abuseipdb

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

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
	abuseIPDB     AbuseIPDB
	maxIPChecks   int
	client        *http.Client
	currentAPIKey string
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
	dummyIP := helpers.GenerateDummyIP()
	for _, key := range a.abuseIPDB.ApiKeys {
		a.setNewKey(key)
		_, err := a.limitChecker(dummyIP)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *abuseIPDBClient) limitChecker(dummyIP string) (int, error) {
	params := url.Values{}
	params.Add("ipAddress", dummyIP)
	params.Add("maxAgeInDays", "90")
	params.Add("verbose", "")
	url := ABUSE_DB_ENDPOINT + "?" + params.Encode()

	res, err := a.client.Get(url)
	if err != nil {
		return 0, e.MakeErr(e.HTTP_GET_ERR, err)
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, e.MakeErr(e.READ_RESPONSE_BODY_ERR, err)
	}

	if res.StatusCode != http.StatusOK {
		return 0, e.MakeErr(fmt.Sprintf("%s, got:%d while excepted status code is: %d, Body: %s", e.INVALID_RESPONSE_CODE, res.StatusCode, http.StatusOK, string(body)), nil)
	}

	remainingChecksStr := res.Header.Get(REMAINING_CHECKS_HEADER)

	if remainingChecksStr == "" {
		return 0, e.MakeErr(fmt.Sprintf("%s, api-key: %s", e.EMPTY_REMAINING_CHECKS_HEADER, a.currentAPIKey), nil)
	}

	remainingChecks, err := strconv.Atoi(remainingChecksStr)
	if err != nil {
		return 0, e.MakeErr(nil, err)
	}

	a.maxIPChecks += remainingChecks
	return 0, nil

}
