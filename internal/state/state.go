package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DefaultStatePath stores dynamic state on tmpfs to avoid router flash wear.
	DefaultStatePath = "/tmp/cf-edge-state.json"
	// DefaultShieldLockPath persists DDoS shield lock across router reboots.
	DefaultShieldLockPath = "/etc/cf-edge/shield.lock"
)

// RuntimeState holds dynamic cached DNS records and daemon runtime metadata.
type RuntimeState struct {
	LastIPv4      string                 `json:"last_ip_v4,omitempty"`
	LastIPv6      string                 `json:"last_ip_v6,omitempty"`
	LastUpdated   time.Time              `json:"last_updated,omitempty"`
	Records       map[string]RecordState `json:"records,omitempty"`
	CFProxyCache  *CFProxyIPCache        `json:"cf_proxy_cache,omitempty"`
	RedialHistory []time.Time            `json:"redial_history,omitempty"`
	PPPoEStatus   *PPPoERuntimeInfo      `json:"pppoe_status,omitempty"`
	PendingNotify []string               `json:"pending_notify,omitempty"`
}

// RecordState caches the Cloudflare DNS record ID and last pushed IP per subdomain/type.
type RecordState struct {
	RecordID  string    `json:"record_id"`
	Subdomain string    `json:"subdomain"`
	Type      string    `json:"type"` // "A" or "AAAA"
	IP        string    `json:"ip"`
	Proxied   bool      `json:"proxied"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CFProxyIPCache caches Cloudflare proxy CIDR ranges fetched from the API.
type CFProxyIPCache struct {
	IPv4CIDRs []string  `json:"ipv4_cidrs,omitempty"`
	IPv6CIDRs []string  `json:"ipv6_cidrs,omitempty"`
	FetchedAt time.Time `json:"fetched_at,omitempty"`
}

// PPPoERuntimeInfo summarizes the latest PPPoE Guard observation for `cf-edge status`.
type PPPoERuntimeInfo struct {
	State       string    `json:"state"`
	LastCheck   time.Time `json:"last_check,omitempty"`
	LastAction  string    `json:"last_action,omitempty"`
	RedialCount int       `json:"redial_count"`
}

// RecordKey constructs the canonical map key for a subdomain and DNS record type.
func RecordKey(subdomain, recordType string) string {
	return subdomain + "|" + recordType
}

// Store provides thread-safe and cross-process-safe access to RuntimeState.
type Store struct {
	path     string
	lockPath string
	mu       sync.Mutex
	data     RuntimeState
	lastMod  time.Time
}

// NewStore creates a state Store backed by the given JSON file path.
func NewStore(path string) *Store {
	if path == "" {
		path = DefaultStatePath
	}
	return &Store{
		path:     path,
		lockPath: path + ".lock",
		data: RuntimeState{
			Records: make(map[string]RecordState),
		},
	}
}

// Path returns the configured state file path.
func (s *Store) Path() string {
	return s.path
}

// Load reads state from disk under lock. Missing file initializes empty state without error.
func (s *Store) Load() (RuntimeState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	unlock, err := acquireFileLock(s.lockPath)
	if err != nil {
		return RuntimeState{}, err
	}
	defer unlock()

	if err := s.loadLocked(); err != nil {
		return RuntimeState{}, err
	}
	return s.data.clone(), nil
}

// Get returns the current state, reloading from disk if modified externally (e.g. via CLI).
func (s *Store) Get() RuntimeState {
	s.mu.Lock()
	defer s.mu.Unlock()

	info, err := os.Stat(s.path)
	if err == nil && !info.ModTime().Equal(s.lastMod) {
		if unlock, lockErr := acquireFileLock(s.lockPath); lockErr == nil {
			_ = s.loadLocked()
			unlock()
		}
	}
	return s.data.clone()
}

// Update atomically loads any newer disk state, applies fn, and persists changes to disk.
func (s *Store) Update(fn func(*RuntimeState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	unlock, err := acquireFileLock(s.lockPath)
	if err != nil {
		return err
	}
	defer unlock()

	if err := s.loadLocked(); err != nil {
		return err
	}

	next := s.data.clone()
	if err := fn(&next); err != nil {
		return err
	}
	if err := s.writeAtomicLocked(next); err != nil {
		return err
	}
	s.data = next
	if info, statErr := os.Stat(s.path); statErr == nil {
		s.lastMod = info.ModTime()
	}
	return nil
}

func (s *Store) loadLocked() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.data = RuntimeState{Records: make(map[string]RecordState)}
			s.lastMod = time.Time{}
			return nil
		}
		return fmt.Errorf("read state %s: %w", s.path, err)
	}

	var parsed RuntimeState
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return fmt.Errorf("decode state %s: %w", s.path, err)
		}
	}
	if parsed.Records == nil {
		parsed.Records = make(map[string]RecordState)
	}
	s.data = parsed
	if info, statErr := os.Stat(s.path); statErr == nil {
		s.lastMod = info.ModTime()
	}
	return nil
}

func (s *Store) writeAtomicLocked(st RuntimeState) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create state dir %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	return writeAtomicFile(s.path, data, 0644)
}

func (st RuntimeState) clone() RuntimeState {
	out := st
	out.Records = make(map[string]RecordState, len(st.Records))
	for k, v := range st.Records {
		out.Records[k] = v
	}
	if st.CFProxyCache != nil {
		cp := *st.CFProxyCache
		cp.IPv4CIDRs = append([]string(nil), st.CFProxyCache.IPv4CIDRs...)
		cp.IPv6CIDRs = append([]string(nil), st.CFProxyCache.IPv6CIDRs...)
		out.CFProxyCache = &cp
	}
	if st.RedialHistory != nil {
		out.RedialHistory = append([]time.Time(nil), st.RedialHistory...)
	}
	if st.PPPoEStatus != nil {
		cp := *st.PPPoEStatus
		out.PPPoEStatus = &cp
	}
	if st.PendingNotify != nil {
		out.PendingNotify = append([]string(nil), st.PendingNotify...)
	}
	return out
}

func writeAtomicFile(targetPath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	tmp, err := os.CreateTemp(dir, filepath.Base(targetPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, targetPath); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpName, targetPath, err)
	}
	cleanup = false
	return nil
}
