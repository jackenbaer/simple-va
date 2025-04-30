package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"sync"
)

type ApiKeyStore struct {
	hashMap map[string]string
	mu      sync.RWMutex
	Enabled bool //decide if apikey authentication is enabled
}

// NewAPIKeyStoreFromFile reads hashed apikeys from a json file and returns them as a map (key = hash, value = comment)
func (s *ApiKeyStore) LoadFromFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	var hashes map[string]string
	decoder := json.NewDecoder(file)

	if err = decoder.Decode(&hashes); err != nil {
		return err
	}
	s.hashMap = hashes

	re := regexp.MustCompile(`^[a-f0-9]{64}$`)
	for key, _ := range s.hashMap {

		if !re.MatchString(key) {
			return errors.New("Key did not match sha256 regex ^[a-f0-9]{64}$")
		}
	}

	return nil
}

// IsAuthorized checks whether the hashed API key is loaded
func (s *ApiKeyStore) IsAuthorized(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hash := sha256.Sum256([]byte(key))
	hashString := hex.EncodeToString(hash[:])

	_, exists := s.hashMap[hashString]
	return exists
}
