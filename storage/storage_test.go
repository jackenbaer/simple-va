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
	if err := db.AddEntry("issuerA", "deadbeef", 1, exp, time.Now(), "KeyCompromise"); err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}
	if err := db.AddEntry("issuerA", "cafebabe", 0, exp, time.Time{}, ""); err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}

	// 3) get & assert
	e1, ok := db.GetEntry("issuerA", "deadbeef")
	if !ok || e1.SerialNumber != "deadbeef" || e1.Status != 1 {
		t.Fatalf("unexpected entry for deadbeef: %+v (found=%v)", e1, ok)
	}

	e2, ok := db.GetEntry("issuerA", "cafebabe")
	if !ok || e2.Status != 0 {
		t.Fatalf("unexpected entry for cafebabe: %+v (found=%v)", e2, ok)
	}

	// 4) reload from disk to prove JSON got written
	dbReload := &CertStatus{
		StatusMap:      make(map[string]map[string]OCSPEntry),
		CertStatusPath: tmpFile,
	}
	if err := dbReload.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if _, ok := dbReload.GetEntry("issuerA", "deadbeef"); !ok {
		t.Fatalf("entry missing after reload")
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
	if err := db.AddEntry("issuerA", "deadbeef", 1, exp, time.Now(), "compromise"); err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}
	if _, ok := db.GetEntry("issuerA", "deadbeef"); !ok {
		t.Fatalf("entry missing after add")
	}

	// --- remove once ---
	ok, err := db.Remove("issuerA", "deadbeef")
	if err != nil {
		t.Fatalf("Remove returned error: %v", err)
	}
	if !ok {
		t.Fatalf("Remove should return true for existing entry")
	}
	if _, ok := db.GetEntry("issuerA", "deadbeef"); ok {
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
	db.AddEntry("issuerX", "expiredSN",
		1, now.Add(-24*time.Hour), now.Add(-24*time.Hour), "superseded")
	db.AddEntry("issuerX", "validSN",
		0, now.Add(24*time.Hour), time.Time{}, "")

	// act
	err := db.RemoveExpired(now)
	if err != nil {
		t.Fatalf("RemoveExpired error: %v", err)
	}

	// verify: expired gone, valid remains
	if _, ok := db.GetEntry("issuerX", "expiredSN"); ok {
		t.Fatalf("expired entry still present after RemoveExpired")
	}
	if _, ok := db.GetEntry("issuerX", "validSN"); !ok {
		t.Fatalf("valid entry missing after RemoveExpired")
	}

	// optionally reload from disk to ensure persistence
	reloaded := &CertStatus{
		StatusMap:      make(map[string]map[string]OCSPEntry),
		CertStatusPath: tmp,
	}
	if err := reloaded.Init(); err != nil {
		t.Fatalf("Init after save failed: %v", err)
	}
	if _, ok := reloaded.GetEntry("issuerX", "validSN"); !ok {
		t.Fatalf("valid entry missing after reload")
	}
	if _, ok := reloaded.GetEntry("issuerX", "expiredSN"); ok {
		t.Fatalf("expired entry resurrected after reload")
	}
}
