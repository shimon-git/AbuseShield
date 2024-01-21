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

type AbuseDBIP struct {
	Enable      bool     `yaml:"enable"`
	Limit       int      `yaml:"limit"`
	Ipv6        bool     `yaml:"ipv6"`
	Ipv4        bool     `yaml:"ipv4"`
	Interval    int      `yaml:"interval"`
	ResultsFile string   `yaml:"results_file"`
	ApiKeys     []string `yaml:"api_keys"`
}

type abuseDbIP struct {
	limit         int
	ipv6          bool
	ipv4          bool
	interval      int
	results       string
	apiKeys       []string
	maxIPChecks   int
	client        *http.Client
	CurrentAPIKey string
}

const (
	CONTENT_TYPE            = "application/json"
	ABUSE_DB_ENDPOINT       = "https://api.abuseipdb.com/api/v2/check"
	REMAINING_CHECKS_HEADER = "X-Ratelimit-Remaining"
)

func New(a AbuseDBIP) *abuseDbIP {
	var abuseDB abuseDbIP
	abuseDB.limit = a.Limit
	abuseDB.ipv4 = a.Ipv4
	abuseDB.ipv6 = a.Ipv6
	abuseDB.interval = a.Interval
	abuseDB.results = a.ResultsFile
	abuseDB.apiKeys = a.ApiKeys

	return &abuseDB
}

func (a *abuseDbIP) setNewKey(apiKey string) {
	httpClient := helpers.HttpClient{
		Headers: map[string]string{
			"Accept": "application/json",
			"Key":    apiKey,
		},
	}
	a.CurrentAPIKey = apiKey
	a.client = httpClient.NewHttpClient()
}

func (a *abuseDbIP) SetMaxIPCHecks() error {
	ip := helpers.GenerateDummyIP()
	for _, key := range a.apiKeys {
		a.setNewKey(key)
		_, err := a.checkIP(ip)
		if err != nil {
			return err
		}
	}
	fmt.Println("Remaining Abuse IP Checks:")
	fmt.Println(a.maxIPChecks)
	return nil
}

func (a *abuseDbIP) checkIP(ip string) (int, error) {
	params := url.Values{}
	params.Add("ipAddress", ip)
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
		return 0, e.MakeErr(fmt.Sprintf("%s, api-key: %s", e.EMPTY_REMAINING_CHECKS_HEADER, a.CurrentAPIKey), nil)
	}

	remainingChecks, err := strconv.Atoi(remainingChecksStr)
	if err != nil {
		return 0, e.MakeErr(nil, err)
	}

	a.maxIPChecks += remainingChecks

	return 0, nil

}
