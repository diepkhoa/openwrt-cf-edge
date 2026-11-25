package state

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStoreLoadUpdateAndExternalReload(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "cf-edge-state.json")
	store := NewStore(statePath)

	initial, err := store.Load()
	if err != nil {
		t.Fatalf("Load empty state failed: %v", err)
	}
	if len(initial.Records) != 0 {
		t.Fatalf("expected empty records, got %d", len(initial.Records))
	}

	err = store.Update(func(st *RuntimeState) error {
		st.LastIPv4 = "1.2.3.4"
		st.LastIPv6 = "2001:db8::1"
		st.Records[RecordKey("wg.example.com", "A")] = RecordState{
			RecordID:  "rec-1",
			Subdomain: "wg.example.com",
			Type:      "A",
			IP:        "1.2.3.4",
			UpdatedAt: time.Now().UTC(),
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	got := store.Get()
	if got.LastIPv4 != "1.2.3.4" || got.Records[RecordKey("wg.example.com", "A")].RecordID != "rec-1" {
		t.Fatalf("unexpected state: %+v", got)
	}

	// Simulate an external CLI process updating the state file.
	cliStore := NewStore(statePath)
	time.Sleep(15 * time.Millisecond)
	if err := cliStore.Update(func(st *RuntimeState) error {
		st.LastIPv4 = "5.6.7.8"
		return nil
	}); err != nil {
		t.Fatalf("CLI Update failed: %v", err)
	}

	reloaded := store.Get()
	if reloaded.LastIPv4 != "5.6.7.8" {
		t.Fatalf("expected reloaded LastIPv4 5.6.7.8, got %q", reloaded.LastIPv4)
	}
}

func TestStoreConcurrentUpdates(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "state.json"))

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := RecordKey(fmt.Sprintf("sub-%d.example.com", idx), "A")
			if err := store.Update(func(st *RuntimeState) error {
				st.Records[key] = RecordState{RecordID: key, IP: "1.1.1.1"}
				return nil
			}); err != nil {
				t.Errorf("concurrent update %d failed: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()

	got := store.Get()
	if len(got.Records) != 20 {
		t.Fatalf("expected 20 records, got %d", len(got.Records))
	}
}

func TestShieldLockLifecycle(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "nested", "shield.lock")

	if IsShielded(lockPath) {
		t.Fatal("IsShielded = true before write")
	}
	if _, exists, err := ReadShieldLock(lockPath); err != nil || exists {
		t.Fatalf("expected non-existent lock, got exists=%v err=%v", exists, err)
	}

	err := WriteShieldLock(lockPath, ShieldLock{
		NodeName:       "x96air",
		Reason:         "conntrack > 5000",
		WANIngressPort: 443,
		ShieldedIPv4:   "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("WriteShieldLock failed: %v", err)
	}
	if !IsShielded(lockPath) {
		t.Fatal("IsShielded = false after write")
	}

	readBack, exists, err := ReadShieldLock(lockPath)
	if err != nil || !exists {
		t.Fatalf("ReadShieldLock failed: exists=%v err=%v", exists, err)
	}
	if !readBack.Active || readBack.NodeName != "x96air" || readBack.WANIngressPort != 443 {
		t.Fatalf("unexpected lock data: %+v", readBack)
	}

	if err := RemoveShieldLock(lockPath); err != nil {
		t.Fatalf("RemoveShieldLock failed: %v", err)
	}
	if IsShielded(lockPath) {
		t.Fatal("IsShielded = true after remove")
	}
	if err := RemoveShieldLock(lockPath); err != nil {
		t.Fatalf("idempotent RemoveShieldLock failed: %v", err)
	}

	// Non-JSON external touch file should still register as active.
	if err := os.MkdirAll(filepath.Dir(lockPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	touched, exists, err := ReadShieldLock(lockPath)
	if err != nil || !exists || !touched.Active {
		t.Fatalf("expected touched file to read as active, got %+v exists=%v err=%v", touched, exists, err)
	}
}
