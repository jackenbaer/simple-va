package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"sync"
)

type ApiKeyStore struct {
	hashMap          map[string]string
	mu               sync.RWMutex
	HashedApiKeyFile string
}

// NewAPIKeyStoreFromFile reads hashed apikeys from a json file and returns them as a map (key = hash, value = comment)
func (s *ApiKeyStore) Init() error {
	file, err := os.Open(s.HashedApiKeyFile)
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
	return nil
}

// IsValidAPIKey checks whether the hashed API key is loaded
func (s *ApiKeyStore) IsValidAPIKey(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hash := sha256.Sum256([]byte(key))
	hashString := hex.EncodeToString(hash[:])

	_, exists := s.hashMap[hashString]
	return exists
}

// Validate checks whether all loaded API keys have in the correct format
func (s *ApiKeyStore) Validate() bool {
	re := regexp.MustCompile(`^[a-f0-9]{64}$`)

	s.mu.RLock()
	defer s.mu.RUnlock()

	for key, _ := range s.hashMap {

		if !re.MatchString(key) {
			return false
		}
	}

	return !(len(s.hashMap) < 1)
}
