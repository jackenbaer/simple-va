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
			name: "single quotes",
			iniData: `
hostname_private_api = localhost:8080
hostname_public_api = localhost:8081
private_key_path = ./simple-va/priv.pem
certificate_path =  ./simple-va/certs/
hashed_api_keys_path = ./testdata/security/hashed_api_keys.json
cert_status_path = ./simple-va/statuslist.json
private_endpoint_cert_path=''
private_endpoint_key_path=""
`,
			wantErr: true,
		},
		{
			name: "comment behind key",
			iniData: `
hostname_private_api = localhost:8080
hostname_public_api = localhost:8081   # testcomment 
private_key_path = ./simple-va/priv.pem
certificate_path =  ./simple-va/certs/
hashed_api_keys_path = ./testdata/security/hashed_api_keys.json
cert_status_path = ./simple-va/statuslist.json
private_endpoint_cert_path=""
private_endpoint_key_path=""
`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp("", "config-*.ini")
			if err != nil {
				t.Fatalf("create temp: %v", err)
			}
			defer os.Remove(tmpfile.Name())

			if _, err := tmpfile.WriteString(tt.iniData); err != nil {
				t.Fatalf("write temp: %v", err)
			}
			tmpfile.Close()

			var cfg Configuration
			err = cfg.LoadFromFile(tmpfile.Name())

			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadFromFile() name = %s, error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}

}
