package main

import (
	"encoding/gob"
	"os"
	"sync"
	"time"
)

// OCSPEntry represents a single OCSP record
type OCSPEntry struct {
	Status           string     // "V" (valid), "R" (revoked), "E" (expired)
	ExpirationDate   time.Time  // Certificate expiration date
	RevocationDate   *time.Time // Revocation date (if revoked)
	RevocationReason string     // Revocation reason (if revoked)
	SerialNumber     string     // Serial number (hex)
}

// OCSPDatabase manages the OCSP entries
type OCSPDatabase struct {
	data map[string]map[string]OCSPEntry // IssuerKeyHash → SerialNumber → OCSPEntry
	mu   sync.RWMutex                    // Allows concurrent reads, exclusive writes
	file string                          // File path for persistence
}

// NewOCSPDatabase initializes the OCSP database
func NewOCSPDatabase(filename string) *OCSPDatabase {
	return &OCSPDatabase{
		data: make(map[string]map[string]OCSPEntry),
		file: filename,
	}
}

// Load reads the OCSP database from disk
func (db *OCSPDatabase) Load() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	file, err := os.Open(db.file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File does not exist, start fresh
		}
		return err
	}
	defer file.Close()

	decoder := gob.NewDecoder(file)
	return decoder.Decode(&db.data)
}

// Save writes the OCSP database to disk
func (db *OCSPDatabase) Save() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	file, err := os.Create(db.file)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	return encoder.Encode(db.data)
}

// AddEntry adds a new OCSP record (allows concurrent reads while locking writes)
func (db *OCSPDatabase) AddEntry(issuerKeyHash, serialNumber, status string, expiration time.Time, revocation *time.Time, reason string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.data[issuerKeyHash]; !exists {
		db.data[issuerKeyHash] = make(map[string]OCSPEntry)
	}

	db.data[issuerKeyHash][serialNumber] = OCSPEntry{
		Status:           status,
		ExpirationDate:   expiration,
		RevocationDate:   revocation,
		RevocationReason: reason,
		SerialNumber:     serialNumber,
	}
}

// GetEntry retrieves an OCSP entry (allows multiple concurrent reads)
func (db *OCSPDatabase) GetEntry(issuerKeyHash, serialNumber string) (OCSPEntry, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	serials, exists := db.data[issuerKeyHash]
	if !exists {
		return OCSPEntry{}, false
	}

	entry, found := serials[serialNumber]
	return entry, found
}
