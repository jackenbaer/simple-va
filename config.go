package main

import (
	"path/filepath"

	"gopkg.in/ini.v1"
)

type Configuration struct {
	HostnamePrivateApi string `ini:"hostname_private_api"`
	HostnamePublicApi  string `ini:"hostname_public_api"`
	PrivateKeyPath     string `ini:"private_key_path"`
	CertsFolderPath    string `ini:"certificate_path"`
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
	return nil
}

/*
parsedPrivateURL, err := url.Parse(hostnamePrivateApi)
if err != nil {
	Logger.Error("Failed to parse URL", "error", err)
	os.Exit(1)
}
parsedPublicURL, err := url.Parse(hostnamePublicApi)
if err != nil {
	Logger.Error("Failed to parse URL", "error", err)
	os.Exit(1)
}
identityFolderPath, err := filepath.Abs(identityFolder)
if err != nil {
	Logger.Error("Error getting absolute path", "error", err)
	os.Exit(1)
}
//

err = ensurePathExists(identityFolderPath)
if err != nil {
	Logger.Error("Error ensuring that path exist", "error", err)
	os.Exit(1)
}
*/
