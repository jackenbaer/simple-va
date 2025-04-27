package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// parseINI reads KEY=VALUE lines into a map (ignores blanks / # comments).
func parseINI(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]string)
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return out, s.Err()
}

// loadConfig fills cfg from a map by matching the struct's `ini` tags.
func loadConfig(m map[string]string, cfg *Configuration) error {
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		tag := t.Field(i).Tag.Get("ini")
		if tag == "" {
			continue
		}
		if val, ok := m[tag]; ok {
			v.Field(i).SetString(val)
		} else {
			return fmt.Errorf("missing ini key %q", tag)
		}
	}
	return nil
}

type Configuration struct {
	HostnamePrivateApi string `ini:"hostname_private_api"`
	HostnamePublicApi  string `ini:"hostname_public_api"`
	PrivateKeyPath     string `ini:"private_key_path"`
	CertsFolderPath    string `ini:"certificate_path"`
	CertStatusPath     string `ini:"cert_status_path"`
	HashedApiKeysPath  string `ini:"hashed_api_keys_path"`
}

func (c *Configuration) LoadFromFile(f string) error {
	absConfigPath, err := filepath.Abs(f)
	if err != nil {
		return err
	}
	iniData, err := parseINI(absConfigPath)
	if err != nil {
		return err
	}

	var cfg Configuration
	if err := loadConfig(iniData, &cfg); err != nil {
		return err
	}
	return nil
}

func (c *Configuration) Validate() error {
	_, err := url.Parse(Config.HostnamePrivateApi)
	if err != nil {
		return err
	}
	_, err = url.Parse(Config.HostnamePublicApi)
	if err != nil {
		return err
	}
	_, err = os.Stat(filepath.Dir(Config.PrivateKeyPath))
	if os.IsNotExist(err) {
		return err
	}
	_, err = os.Stat(Config.CertsFolderPath)
	if os.IsNotExist(err) {
		return err
	}
	_, err = os.Stat(Config.HashedApiKeysPath)
	if os.IsNotExist(err) {
		return err
	}

	return nil
}
