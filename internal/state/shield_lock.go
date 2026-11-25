package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ShieldLock stores persistent metadata in /etc/cf-edge/shield.lock across router reboots.
type ShieldLock struct {
	Active         bool      `json:"active"`
	NodeName       string    `json:"node_name"`
	Reason         string    `json:"reason"`
	Manual         bool      `json:"manual"`
	WANIngressPort int       `json:"wan_ingress_port"`
	ShieldedIPv4   string    `json:"shielded_ipv4,omitempty"`
	ShieldedIPv6   string    `json:"shielded_ipv6,omitempty"`
	EnteredAt      time.Time `json:"entered_at"`
}

func resolveLockPath(path string) string {
	if path == "" {
		return DefaultShieldLockPath
	}
	return path
}

// IsShielded returns true when the persistent shield lock file exists.
func IsShielded(path string) bool {
	_, err := os.Stat(resolveLockPath(path))
	return err == nil
}

// ReadShieldLock reads and decodes the shield lock file.
// If the file exists without valid JSON (e.g. created manually via touch), Active is still true.
func ReadShieldLock(path string) (ShieldLock, bool, error) {
	p := resolveLockPath(path)
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ShieldLock{}, false, nil
		}
		return ShieldLock{}, false, fmt.Errorf("read shield lock %s: %w", p, err)
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return ShieldLock{Active: true, Reason: "external lock file"}, true, nil
	}

	var lock ShieldLock
	if err := json.Unmarshal([]byte(trimmed), &lock); err != nil {
		return ShieldLock{Active: true, Reason: trimmed}, true, nil
	}
	lock.Active = true
	return lock, true, nil
}

// WriteShieldLock atomically writes the shield lock file to flash storage.
func WriteShieldLock(path string, lock ShieldLock) error {
	p := resolveLockPath(path)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return fmt.Errorf("create shield lock dir: %w", err)
	}
	lock.Active = true
	if lock.EnteredAt.IsZero() {
		lock.EnteredAt = time.Now().UTC()
	}
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return fmt.Errorf("encode shield lock: %w", err)
	}
	return writeAtomicFile(p, data, 0644)
}

// RemoveShieldLock removes the shield lock file if present.
func RemoveShieldLock(path string) error {
	p := resolveLockPath(path)
	err := os.Remove(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
