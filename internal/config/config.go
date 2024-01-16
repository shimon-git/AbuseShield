package config

import (
	"fmt"
	"os"

	e "github.com/shimon-git/abuse_checker/internal/errors"
	"github.com/shimon-git/abuse_checker/internal/types"
	"gopkg.in/yaml.v3"
)

func ParseConfig(configFile string) (types.Config, error) {
	var config types.Config
	configReader, err := os.ReadFile(configFile)
	if err != nil {
		return types.Config{}, e.MakeErr(fmt.Sprintf("%s: %s", e.CONFIG_READER_ERROR, configFile), err)
	}

	if err := yaml.Unmarshal(configReader, &config); err != nil {
		return types.Config{}, e.MakeErr(nil, err)
	}

	return config, nil
}
