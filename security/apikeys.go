package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
)

var (
	hashMap map[string]string
	mu      sync.RWMutex
)

// hashSha256 applies sha256 to the input string and returns the hash value
func hashSha256(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// LoadApiKeysFromJsonFile reads hashed apikeys from a json file and returns them as a map (key = hash, value = comment)
func LoadApiKeysFromJsonFile(inputFile string) error {
	file, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	var hashes map[string]string
	decoder := json.NewDecoder(file)

	if err = decoder.Decode(&hashes); err != nil {
		return err
	}

	mu.Lock()
	defer mu.Unlock()
	hashMap = hashes

	return nil
}

// IsValidApiKey checks whether the hashed apikey is loaded
func IsValidApiKey(key string) bool {
	mu.RLock()
	defer mu.RUnlock()

	_, exists := hashMap[hashSha256(key)]
	return exists
}
