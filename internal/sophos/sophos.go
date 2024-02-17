package sophos

import (
	"fmt"
	"io"
	"net/http"

	e "github.com/shimon-git/AbuseShield/internal/errors"
	"github.com/shimon-git/AbuseShield/internal/helpers"
	"go.uber.org/zap"
)

type Sophos struct {
	Enable    bool   `yaml:"enable"`
	Interval  int    `yaml:"interval"`
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	User      string `yaml:"user"`
	Password  string `yaml:"password"`
	GroupName string `yaml:"group_name"`
	Comment   string `yaml:"comment"`
	Ipv6      bool
	Ipv4      bool
	Logger    *zap.Logger
}

type sophosClient struct {
	sophosURL string
	endpoint  map[string]string
	client    *http.Client
	sophos    Sophos
}

func New(s Sophos) *sophosClient {
	var sc sophosClient
	sc.sophos = s
	sc.sophosURL = fmt.Sprintf("https://%s:%d/api", s.Host, s.Port)
	// Initialize the endpoint map
	sc.endpoint = make(map[string]string)
	sc.endpoint["version"] = fmt.Sprintf("%s/status/version", sc.sophosURL)

	httpClient := helpers.HttpClient{
		Headers: map[string]string{
			"content-type": "application/json",
		},
		Auth: helpers.BasicAuth{
			User:     s.User,
			Password: s.Password,
		},
	}

	sc.client = httpClient.NewHttpClient()
	return &sc
}

func (sc *sophosClient) VerifyConnection() error {
	res, err := sc.client.Get(sc.endpoint["version"])
	if err != nil {
		return e.MakeErr(e.HTTP_GET_ERR, err)
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return e.MakeErr(e.READ_RESPONSE_BODY_ERR, err)
	}

	if res.StatusCode != 200 {
		e.MakeErr(fmt.Sprintf("%s got: %d while excepted response is: %d, ResponseBody: %s", e.INVALID_RESPONSE_CODE, http.StatusOK, res.StatusCode, string(body)), nil)
	}
	return nil
}
