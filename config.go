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

func loadConfig(m map[string]string) (Configuration, error) {
	var cfg Configuration
	v := reflect.ValueOf(&cfg).Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("ini")
		if tag == "" {
			continue
		}
		val, ok := m[tag]
		if !ok {
			return Configuration{}, fmt.Errorf("missing ini key %q", tag)
		}
		v.Field(i).SetString(val)
	}
	return cfg, nil
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
	absPath, err := filepath.Abs(f)
	if err != nil {
		return err
	}
	iniData, err := parseINI(absPath)
	if err != nil {
		return err
	}

	loadedCfg, err := loadConfig(iniData)
	if err != nil {
		return err
	}

	*c = loadedCfg
	return nil
}

func (c *Configuration) Validate() error {
	_, err := url.Parse(c.HostnamePrivateApi)
	if err != nil {
		return err
	}
	_, err = url.Parse(c.HostnamePublicApi)
	if err != nil {
		return err
	}
	_, err = os.Stat(filepath.Dir(c.PrivateKeyPath))
	if os.IsNotExist(err) {
		return err
	}
	_, err = os.Stat(c.CertsFolderPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("error opening file %q: %w", c.CertsFolderPath, err)
	}
	_, err = os.Stat(c.HashedApiKeysPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("error opening file %q: %w", c.HashedApiKeysPath, err)
	}

	return nil
}
