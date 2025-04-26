package security

import (
	"testing"
)

func TestHashSha256(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"123", "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"Tc47PO4hMIedGcdg809KiSUkXKH8EpjjM2WSs6Q0ZM", "eea746d000233e477b770212ac1c3120cc458fa43551192de9910e3ae098ef02"},
		{"Super Man", "744deeea2b059f16ceb4860f29baed003e7bd706a5418273753ceae40efcef96"},
		{"dummy14@email.de", "d248723280e75fbd29aaf90974ed224e4adc54fb8617835a14be7fc0085cc461"},
		{"j/3hr93h.,d7fhe3JSHk/6%$§7($&/\"§6-#'*~df", "37dcdb91da663f093c5bf45e103ddb3e486082b7e8357363ca4600f3aaf7e8dd"},
	}

	for _, tt := range tests {
		got := hashSha256(tt.input)

		if got != tt.expected {
			t.Errorf("hashSHA256(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

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
