package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type ApiKeyEntry interface {
	InputApiKeyEntry | HashedApiKeyEntry
}

type InputApiKeyEntry struct {
	Key     string `json:"key"`
	Comment string `json:"comment"`
}

type HashedApiKeyEntry struct {
	Hash    string `json:"hash"`
	Comment string `json:"comment"`
}

func HashInputApiKeys(entries []InputApiKeyEntry) []HashedApiKeyEntry {
	const RECOMMENDED_KEY_LENGTH = 32
	var hashedEntries []HashedApiKeyEntry
	// hash api keys
	for index, entry := range entries {
		if len(entry.Key) == 0 {
			fmt.Printf("Invalid entry at index %d (comment: %s)\n", index, entry.Comment)
			continue
		}
		if len(entry.Key) < RECOMMENDED_KEY_LENGTH {
			fmt.Printf("Keys with at least %d characters are recommended.\n", RECOMMENDED_KEY_LENGTH)
		}
		hash := sha256.Sum256([]byte(entry.Key))

		hashedEntry := HashedApiKeyEntry{
			Hash:    hex.EncodeToString(hash[:]),
			Comment: entry.Comment,
		}

		hashedEntries = append(hashedEntries, hashedEntry)
	}

	return hashedEntries
}

func WriteHashedApiKeysToJsonFile(outputFile string, entries []HashedApiKeyEntry) error {
	oFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer oFile.Close()

	// struct to json
	encoder := json.NewEncoder(oFile)
	encoder.SetIndent("", " ")
	err = encoder.Encode(entries)
	if err != nil {
		return err
	}

	return nil
}

func ReadApiKeysFromJsonFile[T ApiKeyEntry](inputFile string) []T {
	// try to read input file
	iFile, err := os.Open(inputFile)
	if err != nil {
		return nil
	}
	defer iFile.Close()

	// json to struct
	var apiKeyEntries []T
	decoder := json.NewDecoder(iFile)

	err = decoder.Decode(&apiKeyEntries)
	if err != nil {
		fmt.Println("No valid API key entries in input file.")
		return nil
	}

	return apiKeyEntries
}

// inputFile: path + filename
func HashInputApiKeysFromFile(inputFile string, outputFile string, deleteInputFile bool) bool {
	// try to read input file
	inputApiKeyEntries := ReadApiKeysFromJsonFile[InputApiKeyEntry](inputFile)
	if inputApiKeyEntries == nil {
		return false
	}

	fmt.Println("Hashing API keys...")

	hashedEntries := HashInputApiKeys(inputApiKeyEntries)
	if hashedEntries == nil {
		fmt.Println("No API keys in input file defined.")
		return false
	}
	fmt.Println("API keys hashed.")

	err := WriteHashedApiKeysToJsonFile(outputFile, hashedEntries)
	if err != nil {
		fmt.Println("Error when writing/encoding hashed API keys:", err)
		return false
	}
	fmt.Println("Hashed API keys saved.")

	// delete input file
	if deleteInputFile {
		err := os.Remove(inputFile)
		if err != nil {
			fmt.Println("Input file couldn't be removed:", err)
		}
		fmt.Println("API key input file removed.")
	}

	return true
}

func LoadHashedApiKeysFromFile(inputFile string) []HashedApiKeyEntry {
	apiKeyEntries := ReadApiKeysFromJsonFile[HashedApiKeyEntry](inputFile)
	if apiKeyEntries == nil {
		return nil
	}
	fmt.Println("Hashed API keys loaded.")
	return apiKeyEntries
}
