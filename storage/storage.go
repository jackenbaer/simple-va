package storage

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// OCSPEntry represents a single OCSP record
type OCSPEntry struct {
	Status           int       `json:"status"`            //Good = 0, Revoked = 1, Unknown = 2, here just revoked or not in list
	ExpirationDate   time.Time `json:"expiration_date"`   // Certificate expiration date
	RevocationDate   time.Time `json:"revocation_date"`   // Revocation date
	RevocationReason string    `json:"revocation_reason"` // Revocation reason
	SerialNumber     string    `json:"serial_number"`     // Serial number (hex)
}

// CertStatus manages the OCSP entries
type CertStatus struct {
	StatusMap      map[string]map[string]OCSPEntry // IssuerKeyHash → SerialNumber → OCSPEntry
	mu             sync.RWMutex                    // Allows concurrent reads, exclusive writes
	CertStatusPath string
}

func (db *CertStatus) Init() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	file, err := os.Open(db.CertStatusPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()
	dec := json.NewDecoder(file)
	err = dec.Decode(&db.StatusMap)
	if err != nil {
		return err
	}
	return nil
}

func (db *CertStatus) saveJsonToDisk() error {
	file, err := os.Create(db.CertStatusPath)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(db.StatusMap)
}

func (db *CertStatus) AddEntry(issuerKeyHash string, entry OCSPEntry) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.StatusMap[issuerKeyHash]; !exists {
		db.StatusMap[issuerKeyHash] = make(map[string]OCSPEntry)
	}

	db.StatusMap[issuerKeyHash][entry.SerialNumber] = entry
	err := db.saveJsonToDisk()
	if err != nil {
		return err
	}
	return nil
}

func (db *CertStatus) GetEntry(issuerKeyHash, serialNumber string) (OCSPEntry, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	serials, exists := db.StatusMap[issuerKeyHash]
	if !exists {
		return OCSPEntry{}, false
	}

	entry, found := serials[serialNumber]
	return entry, found
}

func (db *CertStatus) Remove(issuerKeyHash, serialNumber string) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	serials, ok := db.StatusMap[issuerKeyHash]
	if !ok {
		return false, nil
	}
	if _, found := serials[serialNumber]; !found {
		return false, nil
	}
	delete(serials, serialNumber)
	if len(serials) == 0 {
		delete(db.StatusMap, issuerKeyHash)
	}

	err := db.saveJsonToDisk()
	return true, err
}

// RemoveExpired drops every entry whose ExpirationDate is before now without blocking parallel readers while it scans.
func (db *CertStatus) RemoveExpired(now time.Time) error {
	//create copy of map under read lock
	db.mu.RLock()
	newMap := make(map[string]map[string]OCSPEntry, len(db.StatusMap))
	removed := 0

	for issuer, serials := range db.StatusMap {
		for sn, entry := range serials {
			if entry.ExpirationDate.Before(now) {
				removed++
				continue // skip expired
			}
			// keep a copy
			if _, ok := newMap[issuer]; !ok {
				newMap[issuer] = make(map[string]OCSPEntry)
			}
			newMap[issuer][sn] = entry
		}
	}
	db.mu.RUnlock()

	if removed == 0 {
		return nil
	}

	//atomically swap the map under write-lock
	db.mu.Lock()
	db.StatusMap = newMap
	err := db.saveJsonToDisk()
	db.mu.Unlock()

	return err
}
