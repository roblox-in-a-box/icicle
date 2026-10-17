package main

import (
	"encoding/json"
	"errors"
	"os"
)

type fileConfig struct {
	Admins map[string]bool `json:"Admins"`
}

func loadConfig(path string, required bool) (fileConfig, error) {
	var config fileConfig
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !required {
		return config, nil
	}
	if err != nil {
		return config, err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return config, err
	}
	return config, nil
}
