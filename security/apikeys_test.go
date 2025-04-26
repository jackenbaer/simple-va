package security

import (
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
			inputFile: "../testdata/hashed_api_keys.json",
			wantErr:   false,
		},
		{
			name:      "empty file",
			inputFile: "../testdata/invalid_hashed_api_keys_1.json",
			wantErr:   true,
		},
		{
			name:      "typing error",
			inputFile: "../testdata/invalid_hashed_api_keys_4.json",
			wantErr:   true,
		},
		{
			name:      "file does not exist",
			inputFile: "../testdata/invalid_hashed_api_keys_not_exist.json",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAPIKeyStoreFromFile(tt.inputFile)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewAPIKeyStoreFromFile(%q) error = %v, wantErr %v", tt.inputFile, err, tt.wantErr)
			}
		})
	}
}

func TestIsValidApiKey(t *testing.T) {
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
	APIKeyStore, err := NewAPIKeyStoreFromFile("../testdata/hashed_api_keys.json")
	if err != nil {
		t.Errorf("Preparing TestIsValidApiKey. Error = %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if APIKeyStore.IsValidAPIKey(tt.testKey) == tt.wantErr {
				t.Errorf("IsValidApiKey(%q), wantErr %v", tt.testKey, tt.wantErr)
			}
		})
	}
}

func TestAllAPIKeysValid(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		wantErr   bool
	}{
		{
			name:      "valid file",
			inputFile: "../testdata/hashed_api_keys.json",
			wantErr:   false,
		},
		{
			name:      "empty file",
			inputFile: "../testdata/invalid_hashed_api_keys_2.json",
			wantErr:   true,
		},
		{
			name:      "typing error",
			inputFile: "../testdata/invalid_hashed_api_keys_3.json",
			wantErr:   true,
		},
		{
			name:      "uppercase chars in key",
			inputFile: "../testdata/invalid_hashed_api_keys_5.json",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			APIKeyStore, err := NewAPIKeyStoreFromFile(tt.inputFile)

			if err != nil {
				t.Errorf("Preparing TestAllAPIKeysValid() error = %v", err)
			}

			if APIKeyStore.AllAPIKeysValid() == tt.wantErr {
				t.Errorf("AllAPIKeysValid() for %q, error = %v, wantErr %v", tt.inputFile, err, tt.wantErr)
			}
		})
	}
}
