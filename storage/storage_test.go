package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAddAndGet(t *testing.T) {
	// 1) prepare empty DB in a temp directory
	tmpFile := filepath.Join(t.TempDir(), "ocsp.json")
	db := &CertStatus{
		StatusMap:      make(map[string]map[string]OCSPEntry),
		CertStatusPath: tmpFile,
	}

	// 2) add two entries
	exp := time.Now().Add(365 * 24 * time.Hour)
	if err := db.AddEntry("issuerA", OCSPEntry{SerialNumber: "deadbeef", Status: 1, ExpirationDate: exp, RevocationDate: time.Now(), RevocationReason: "KeyCompromise"}); err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}
	if err := db.AddEntry("issuerA", OCSPEntry{SerialNumber: "cafebabe", Status: 0, ExpirationDate: exp, RevocationDate: time.Time{}, RevocationReason: ""}); err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}

	// 3) get & assert
	e1, err := db.GetEntry("issuerA", "deadbeef")
	if err != nil {
		t.Fatalf("unexpected error for deadbeef: %v", err)
	}
	if e1.SerialNumber != "deadbeef" || e1.Status != 1 {
		t.Fatalf("unexpected entry for deadbeef: %+v", e1)
	}

	e2, err := db.GetEntry("issuerA", "cafebabe")
	if err != nil {
		t.Fatalf("unexpected error for cafebabe: %v", err)
	}
	if e2.Status != 0 {
		t.Fatalf("unexpected entry for cafebabe: %+v", e2)
	}

	// 4) reload from disk to prove JSON got written
	dbReload := &CertStatus{
		StatusMap:      make(map[string]map[string]OCSPEntry),
		CertStatusPath: tmpFile,
	}
	if err := dbReload.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if _, err := dbReload.GetEntry("issuerA", "deadbeef"); err != nil {
		t.Fatalf("entry missing after reload: %v", err)
	}
}

func TestRemove(t *testing.T) {
	// temp DB file
	tmp := filepath.Join(t.TempDir(), "ocsp.json")

	db := &CertStatus{
		StatusMap:      make(map[string]map[string]OCSPEntry),
		CertStatusPath: tmp,
	}

	// prepare data
	exp := time.Now().Add(24 * time.Hour)
	if err := db.AddEntry("issuerA", OCSPEntry{SerialNumber: "deadbeef", Status: 1, ExpirationDate: exp, RevocationDate: time.Now(), RevocationReason: "compromise"}); err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}
	if _, err := db.GetEntry("issuerA", "deadbeef"); err != nil {
		t.Fatalf("entry missing after add: %v", err)
	}

	// --- remove once ---
	ok, err := db.Remove("issuerA", "deadbeef")
	if err != nil {
		t.Fatalf("Remove returned error: %v", err)
	}
	if !ok {
		t.Fatalf("Remove should return true for existing entry")
	}
	if _, err := db.GetEntry("issuerA", "deadbeef"); err == nil {
		t.Fatalf("entry still present after Remove")
	}

	// --- remove again (should be no-op) ---
	ok, err = db.Remove("issuerA", "deadbeef")
	if err != nil {
		t.Fatalf("second Remove error: %v", err)
	}
	if ok {
		t.Fatalf("second Remove should return false (nothing to delete)")
	}
}

func TestRemoveExpired(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "ocsp.json")

	db := &CertStatus{
		StatusMap:      make(map[string]map[string]OCSPEntry),
		CertStatusPath: tmp,
	}

	now := time.Now()

	// add one expired, one still valid
	db.AddEntry("issuerX", OCSPEntry{SerialNumber: "expiredSN", Status: 1, ExpirationDate: now.Add(-24 * time.Hour), RevocationDate: now.Add(-24 * time.Hour), RevocationReason: "superseded"})
	db.AddEntry("issuerX", OCSPEntry{SerialNumber: "validSN", Status: 0, ExpirationDate: now.Add(24 * time.Hour), RevocationDate: time.Time{}, RevocationReason: ""})

	// act
	if err := db.RemoveExpired(now); err != nil {
		t.Fatalf("RemoveExpired error: %v", err)
	}

	// verify: expired gone, valid remains
	if _, err := db.GetEntry("issuerX", "expiredSN"); err == nil {
		t.Fatalf("expired entry still present after RemoveExpired")
	}
	if _, err := db.GetEntry("issuerX", "validSN"); err != nil {
		t.Fatalf("valid entry missing after RemoveExpired: %v", err)
	}

	// optionally reload from disk to ensure persistence
	reloaded := &CertStatus{
		StatusMap:      make(map[string]map[string]OCSPEntry),
		CertStatusPath: tmp,
	}
	if err := reloaded.Init(); err != nil {
		t.Fatalf("Init after save failed: %v", err)
	}
	if _, err := reloaded.GetEntry("issuerX", "validSN"); err != nil {
		t.Fatalf("valid entry missing after reload: %v", err)
	}
	if _, err := reloaded.GetEntry("issuerX", "expiredSN"); err == nil {
		t.Fatalf("expired entry resurrected after reload")
	}
}
