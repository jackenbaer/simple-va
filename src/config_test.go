package main

import (
	"os"
	"testing"
)

func TestConfigurationLoadAndValidate(t *testing.T) {
	tests := []struct {
		name    string
		iniData string
		wantErr bool
	}{
		{
			name: "missing required key",
			iniData: `
hostname_private_api = localhost:8080
private_key_path = ./simple-va/priv.pem
certificate_path = ./simple-va/certs/
hashed_api_keys_path = ./testdata/security/hashed_api_keys.json
cert_status_path = ./simple-va/status.json
private_endpoint_cert_path=""
private_endpoint_key_path=""
`,
			wantErr: true,
		},
		{
			name: "valid config",
			iniData: `
hostname_private_api = localhost:8080
hostname_public_api = localhost:8081
private_key_path = ./simple-va/priv.pem
certificate_path =  ./simple-va/certs/
hashed_api_keys_path = ./testdata/security/hashed_api_keys.json
cert_status_path = ./simple-va/statuslist.json
private_endpoint_cert_path=""
private_endpoint_key_path=""
`,
			wantErr: false,
		},
		{
			name: "invalid ini line",
			iniData: `
hostname_private_api  localhost:8080
hostname_public_api = localhost:8081
private_key_path = ./simple-va/priv.pem
certificate_path =  ./simple-va/certs/
hashed_api_keys_path = ./testdata/security/hashed_api_keys.json
cert_status_path = ./simple-va/statuslist.json
private_endpoint_cert_path=""
private_endpoint_key_path=""
`,
			wantErr: true,
		},
		{
			name: "invalid delimiter",
			iniData: `
hostname_private_api = localhost:8080
hostname_public_api = localhost:8081
private_key_path = ./simple-va/priv.pem
certificate_path =  ./simple-va/certs/
hashed_api_keys_path = ./testdata/security/hashed_api_keys.json
cert_status_path : ./simple-va/statuslist.json
private_endpoint_cert_path=""
private_endpoint_key_path=""
`,
			wantErr: true,
		},
		{
			name: "invalid path",
			iniData: `
hostname_private_api = localhost:8080
hostname_public_api = localhost:8081
private_key_path = ./simple-va/priv.pem
certificate_path =  ./simple-va/certs/
hashed_api_keys_path = ./testdata/security/hashed_api_keys.json
cert_status_path =  /test ./simple-va/statuslist.json
private_endpoint_cert_path=""
private_endpoint_key_path=""

`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp("", "config-*.ini")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpfile.Name()) // Clean up

			_, err = tmpfile.WriteString(tt.iniData)
			if err != nil {
				t.Fatalf("failed to write config to temp file: %v", err)
			}
			err = tmpfile.Close()
			if err != nil {
				t.Fatalf("failed to close temp file: %v", err)
			}

			var cfg Configuration
			err = cfg.LoadFromFile(tmpfile.Name())
			if err != nil && !tt.wantErr {
				t.Errorf("LoadFromFile failed: %v", err)
				return
			}
			err = cfg.Validate()
			if err != nil && !tt.wantErr {
				t.Errorf("unexpected validation result: got error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}

}
