package main

import (
	"path/filepath"
	"testing"
)

func TestNewAPIKeyStoreFromFile(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		wantErr   bool
	}{
		{
			name:      "valid file",
			inputFile: "../testdata/security/hashed_api_keys.json",
			wantErr:   false,
		},
		{
			name:      "empty file",
			inputFile: "../testdata/security/invalid_hashed_api_keys_1.json",
			wantErr:   true,
		},
		{
			name:      "typing error",
			inputFile: "../testdata/security/invalid_hashed_api_keys_4.json",
			wantErr:   true,
		},
		{
			name:      "file does not exist",
			inputFile: "../testdata/security/invalid_hashed_api_keys_not_exist.json",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			absPath := filepath.Clean(tt.inputFile)

			a := ApiKeyStore{HashedApiKeyFile: absPath}
			err := a.Init()

			if (err != nil) != tt.wantErr {
				t.Errorf("Init(%q) error = %v, wantErr %v", tt.inputFile, err, tt.wantErr)
			}
		})
	}
}

func TestIsAuthorized(t *testing.T) {
	tests := []struct {
		name    string
		testKey string
		wantErr bool
	}{
		{
			name:    "valid",
			testKey: "123",
			wantErr: false,
		},
		{
			name:    "valid",
			testKey: "dummy14@email.de",
			wantErr: false,
		},
		{
			name:    "valid",
			testKey: "Tc47PO4hMIedGcdg809KiSUkXKH8EpjjM2WSs6Q0ZM",
			wantErr: false,
		},
		{
			name:    "not valid",
			testKey: "Tc47PO4hMIedGcdg809KiSUkXKH8EpjjM2WSs6Q0ZN",
			wantErr: true,
		},
		{
			name:    "not valid",
			testKey: "Tc47PO4hMIedGcdg809KiSUkXKH8EpjjM2WSs6Q0ZN",
			wantErr: true,
		},
		{
			name:    "valid",
			testKey: "j/3hr93h.,d7fhe3JSHk/6%$§7($&/\"§6-#'*~df",
			wantErr: false,
		},
	}

	a := ApiKeyStore{HashedApiKeyFile: "../testdata/security/hashed_api_keys.json"}
	err := a.Init()
	if err != nil {
		t.Errorf("Init(), %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if a.IsAuthorized(tt.testKey) == tt.wantErr {
				t.Errorf("IsAuthorized(%q), wantErr %v", tt.testKey, tt.wantErr)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		valid     bool
	}{
		{
			name:      "valid file",
			inputFile: "../testdata/security/hashed_api_keys.json",
			valid:     false,
		},
		{
			name:      "empty file",
			inputFile: "../testdata/security/invalid_hashed_api_keys_2.json",
			valid:     true,
		},
		{
			name:      "typing error",
			inputFile: "../testdata/security/invalid_hashed_api_keys_3.json",
			valid:     true,
		},
		{
			name:      "uppercase chars in key",
			inputFile: "../testdata/security/invalid_hashed_api_keys_5.json",
			valid:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			absPath := filepath.Clean(tt.inputFile)

			a := ApiKeyStore{HashedApiKeyFile: absPath}
			err := a.Init()
			if err != nil {
				t.Errorf("Init(), %v", err)
			}

			if a.Validate() == tt.valid {
				t.Errorf("Validate() for %q, valid %v", tt.inputFile, tt.valid)
			}
		})
	}
}
