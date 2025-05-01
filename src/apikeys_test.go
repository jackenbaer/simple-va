package main

import (
	"os"
	"testing"
)

func TestNewAPIKeyStoreFromFile(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{
			name: "valid file",
			data: `
{
  "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3": "123",
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad": "abc",
  "eea746d000233e477b770212ac1c3120cc458fa43551192de9910e3ae098ef02": "Tc47PO4hMIedGcdg809KiSUkXKH8EpjjM2WSs6Q0ZM",
  "744deeea2b059f16ceb4860f29baed003e7bd706a5418273753ceae40efcef96": "Super Man",
  "d248723280e75fbd29aaf90974ed224e4adc54fb8617835a14be7fc0085cc461": "dummy14@email.de",
  "37dcdb91da663f093c5bf45e103ddb3e486082b7e8357363ca4600f3aaf7e8dd": "j/3hr93h.,d7fhe3JSHk/6%$§7($&/\"§6-#'*~df"
 }
`,
			wantErr: false,
		},
		{
			name:    "empty file",
			data:    ``,
			wantErr: true,
		},
		{
			name: "typing error",
			data: `
{
    "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3": "123",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad": "abc",
    "eea746d000233e477b770212ac1c3120cc458fa43551192de9910e3ae098ef02": "Tc47PO4hMIedGcdg809KiSUkXKH8EpjjM2WSs6Q0ZM",
    "744deeea2b059f16ceb4860f29baed003e7bd706a5418273753ceae40efcef96": "Super Man",
    "": "dummy14@email.de",
    "37dcdb91da663f093c5bf45e103ddb3e486082b7e8357363ca4600f3aaf7e8dd": "j/3hr93h.,d7fhe3JSHk/6%$§7($&/\"§6-#'*~df"
   }
`,
			wantErr: true,
		},

		{
			name: " error",
			data: `
 {
  "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3": "123",
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad": "abc",
  "eea746d000233e477b770212ac1c3120cc458fa43551192de9910e3ae098ef02": "Tc47PO4hMIedGcdg809KiSUkXKH8EpjjM2WSs6Q0ZM",
  "744deeea2b059f16ceb4860f29baed003e7bd706a5418273753ceae40efcef96": "Super Man",
  "d248723280e75fbd29aaf90974ed224e4adc54fb8617835a14be7fc0085cc461": "dummy14@email.de",
  "37dcdb91da663f093c5bf45e103ddb3e486082b7e8357363ca4600f3aaf7e8DD": "j/3hr93h.,d7fhe3JSHk/6%$§7($&/\"§6-#'*~df"
 }
`,
			wantErr: true,
		},
		{
			name: "error",
			data: `
{
    "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3": "123",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad": "abc",
    "eea746d000233e477b770212ac1c3120cc458fa43551192de9910e3ae098ef02: "Tc47PO4hMIedGcdg809KiSUkXKH8EpjjM2WSs6Q0ZM",
    "744deeea2b059f16ceb4860f29baed003e7bd706a5418273753ceae40efcef96": "Super Man",
    "d248723280e75fbd29aaf90974ed224e4adc54fb8617835a14be7fc0085cc461": "dummy14@email.de"
}
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp("", "apikey-*.json")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpfile.Name()) // Clean up

			_, err = tmpfile.WriteString(tt.data)
			if err != nil {
				t.Fatalf("failed to write config to temp file: %v", err)
			}
			err = tmpfile.Close()
			if err != nil {
				t.Fatalf("failed to close temp file: %v", err)
			}

			a := ApiKeyStore{}
			err = a.LoadFromFile(tmpfile.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadFromFile(%q) name = %s,  error = %v, wantErr %v", tt.data, tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestIsAuthenticated(t *testing.T) {
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

	data := `
	 {
  "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3": "123",
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad": "abc",
  "eea746d000233e477b770212ac1c3120cc458fa43551192de9910e3ae098ef02": "Tc47PO4hMIedGcdg809KiSUkXKH8EpjjM2WSs6Q0ZM",
  "744deeea2b059f16ceb4860f29baed003e7bd706a5418273753ceae40efcef96": "Super Man",
  "d248723280e75fbd29aaf90974ed224e4adc54fb8617835a14be7fc0085cc461": "dummy14@email.de",
  "37dcdb91da663f093c5bf45e103ddb3e486082b7e8357363ca4600f3aaf7e8dd": "j/3hr93h.,d7fhe3JSHk/6%$§7($&/\"§6-#'*~df"
 }`
	tmpfile, err := os.CreateTemp("", "apikey-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name()) // Clean up

	_, err = tmpfile.WriteString(data)
	if err != nil {
		t.Fatalf("failed to write config to temp file: %v", err)
	}
	err = tmpfile.Close()
	if err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	a := ApiKeyStore{}
	err = a.LoadFromFile(tmpfile.Name())
	if err != nil {
		t.Errorf("Init(), %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if a.IsAuthenticated(tt.testKey) == tt.wantErr {
				t.Errorf("IsAuthenticated(%q), wantErr %v", tt.testKey, tt.wantErr)
			}
		})
	}
}
