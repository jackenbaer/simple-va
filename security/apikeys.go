package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
)

type APIKeyStore struct {
	hashMap map[string]string
	mu      sync.RWMutex
}

// NewAPIKeyStoreFromFile reads hashed apikeys from a json file and returns them as a map (key = hash, value = comment)
func NewAPIKeyStoreFromFile(inputFile string) (*APIKeyStore, error) {
	file, err := os.Open(inputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hashes map[string]string
	decoder := json.NewDecoder(file)

	if err = decoder.Decode(&hashes); err != nil {
		return nil, err
	}

	return &APIKeyStore{
		hashMap: hashes,
	}, nil
}

// IsValidAPIKey checks whether the hashed apikey is loaded
func (s *APIKeyStore) IsValidAPIKey(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hash := sha256.Sum256([]byte(key))
	hashString := hex.EncodeToString(hash[:])

	_, exists := s.hashMap[hashString]
	return exists
}

func (s *APIKeyStore) AllAPIKeysValid() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	const MIN_KEYS_REQUIRED = 1

	for key, _ := range s.hashMap {
		if len(key) < 64 {
			return false
		}
	}

	return !(len(s.hashMap) < MIN_KEYS_REQUIRED)
}
