package main

import (
	"path/filepath"
	"testing"
)

func TestConfigurationLoadAndValidate(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		wantErr   bool
		parseOnly bool // skip validation step if true
	}{
		{
			name:      "missing required key",
			inputFile: "testdata/config/invalid_config_1.ini",
			wantErr:   true,
		},
		{
			name:      "valid config",
			inputFile: "testdata/config/valid_config.ini",
			wantErr:   false,
		},
		{
			name:      "invalid ini line",
			inputFile: "testdata/config/invalid_config_2.ini",
			wantErr:   true,
		},
		{
			name:      "invalid delimiter",
			inputFile: "testdata/config/invalid_config_3.ini",
			wantErr:   true,
		},
		{
			name:      "invalid path",
			inputFile: "testdata/config/invalid_config_4.ini",
			wantErr:   true,
		},
		{
			name:      "file does not exist",
			inputFile: "testdata/config/invalid_config_5.ini",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			absPath := filepath.Clean(tt.inputFile)

			var cfg Configuration
			err := cfg.LoadFromFile(absPath)

			if err != nil && !tt.wantErr {
				t.Errorf("Loading Error (%q) error = %v", absPath, err)

			}

			err = cfg.Validate()
			if err != nil && !tt.wantErr {
				t.Errorf("Validation Error (%q) error = %v", absPath, err)
			}
		})
	}
}
