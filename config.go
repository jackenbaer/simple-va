package main

import (
	"net/url"
	"os"
	"path/filepath"

	"gopkg.in/ini.v1"
)

type Configuration struct {
	HostnamePrivateApi    string `ini:"hostname_private_api"`
	HostnamePublicApi     string `ini:"hostname_public_api"`
	PrivateKeyPath        string `ini:"private_key_path"`
	CertsFolderPath       string `ini:"certificate_path"`
	InputApiKeysPath      string `ini:"input_api_keys_path"`
	HashedApiKeysPath     string `ini:"hashed_api_keys_path"`
	DeleteInputApiKeyFile bool   `ini:"delete_input_api_key_file"`
}

func (c *Configuration) LoadFromFile(f string) error {
	absConfigPath, err := filepath.Abs(f)
	if err != nil {
		return err
	}
	cfg, err := ini.Load(absConfigPath)
	if err != nil {
		return err
	}
	Config = &Configuration{}

	err = cfg.MapTo(&Config)
	if err != nil {
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
	_, err = os.Stat(Config.InputApiKeysPath)
	if os.IsNotExist(err) {
		// hashed api keys required
		_, err = os.Stat(Config.HashedApiKeysPath)
		if os.IsNotExist(err) {
			return err
		}
	}
	_, err = os.Stat(Config.HashedApiKeysPath)
	if os.IsNotExist(err) {
		// input api keys required
		_, err = os.Stat(Config.InputApiKeysPath)
		if os.IsNotExist(err) {
			return err
		}
	}

	return nil
}
