package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Channel struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	BaseURL    string            `json:"base_url"`
	APIKey     string            `json:"api_key,omitempty"`
	AuthHeader string            `json:"auth_header,omitempty"`
	AuthPrefix string            `json:"auth_prefix,omitempty"`
	Group      string            `json:"group"`
	Models     []string          `json:"models"`
	Mapping    map[string]string `json:"model_mapping,omitempty"`
	Priority   int               `json:"priority"`
	Weight     int               `json:"weight"`
	Enabled    bool              `json:"enabled"`
	CreatedAt  time.Time         `json:"created_at"`
}

type Key struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Digest      string    `json:"digest"`
	Prefix      string    `json:"prefix"`
	Group       string    `json:"group"`
	Models      []string  `json:"models,omitempty"`
	Enabled     bool      `json:"enabled"`
	QuotaTokens int64     `json:"quota_tokens,omitempty"`
	UsedTokens  int64     `json:"used_tokens"`
	CreatedAt   time.Time `json:"created_at"`
}

type Usage struct {
	ID               string    `json:"id"`
	KeyID            string    `json:"key_id"`
	ChannelID        string    `json:"channel_id"`
	Model            string    `json:"model"`
	UpstreamModel    string    `json:"upstream_model"`
	PromptTokens     int64     `json:"prompt_tokens"`
	CompletionTokens int64     `json:"completion_tokens"`
	StatusCode       int       `json:"status_code"`
	LatencyMS        int64     `json:"latency_ms"`
	Error            string    `json:"error,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

type snapshot struct {
	Channels map[string]json.RawMessage `json:"channels"`
	Keys     map[string]Key             `json:"keys"`
	Usage    []Usage                    `json:"usage,omitempty"`
}

type Store struct {
	mu        sync.RWMutex
	path      string
	secretKey []byte
	channels  map[string]Channel
	keys      map[string]Key
	usage     []Usage
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	secretKey, fallbackKeys, err := loadEncryptionKeys(path)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, secretKey: secretKey, channels: map[string]Channel{}, keys: map[string]Key{}}
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	migrate := false
	if err == nil {
		var snap snapshot
		if err := json.Unmarshal(b, &snap); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		for id, raw := range snap.Channels {
			var c Channel
			if err := json.Unmarshal(raw, &c); err != nil {
				return nil, fmt.Errorf("decode channel %s: %w", id, err)
			}
			storedCredential := c.APIKey
			c.APIKey, err = decryptSecret(secretKey, storedCredential)
			if err != nil && strings.HasPrefix(storedCredential, "enc:v1:") {
				for _, fallback := range fallbackKeys {
					c.APIKey, err = decryptSecret(fallback, storedCredential)
					if err == nil {
						migrate = true
						break
					}
				}
			}
			if err != nil {
				return nil, fmt.Errorf("decrypt channel %s credential: %w", id, err)
			}
			if c.APIKey != "" && !strings.HasPrefix(stringField(raw, "api_key"), "enc:v1:") {
				migrate = true
			}
			s.channels[id] = c
		}
		if snap.Keys != nil {
			s.keys = snap.Keys
		}
		s.usage = snap.Usage
	}
	if migrate {
		if err := s.persistLocked(); err != nil {
			return nil, fmt.Errorf("encrypt existing channel credentials: %w", err)
		}
	}
	if err := saveEncryptionKey(path+".key", secretKey); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	channels := make(map[string]json.RawMessage, len(s.channels))
	for id, channel := range s.channels {
		encrypted, err := encryptSecret(s.secretKey, channel.APIKey)
		if err != nil {
			return err
		}
		channel.APIKey = encrypted
		encoded, err := json.Marshal(channel)
		if err != nil {
			return err
		}
		channels[id] = encoded
	}
	b, err := json.MarshalIndent(snapshot{Channels: channels, Keys: s.keys, Usage: s.usage}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := writeSecureFile(tmp, b); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func loadEncryptionKeys(statePath string) ([]byte, [][]byte, error) {
	keyPath := statePath + ".key"
	storedKey, fileErr := os.ReadFile(keyPath)
	if fileErr == nil && len(storedKey) != 32 {
		return nil, nil, fmt.Errorf("invalid encryption key file %s", keyPath)
	}
	if fileErr != nil && !errors.Is(fileErr, os.ErrNotExist) {
		return nil, nil, fileErr
	}
	if configured := strings.TrimSpace(os.Getenv("MASTER_KEY")); configured != "" {
		key, err := hex.DecodeString(configured)
		if err != nil || len(key) != 32 {
			return nil, nil, errors.New("MASTER_KEY must be 64 hexadecimal characters (32 bytes)")
		}
		var fallback [][]byte
		if len(storedKey) == 32 && subtle.ConstantTimeCompare(key, storedKey) != 1 {
			fallback = append(fallback, storedKey)
		}
		return key, fallback, nil
	}
	if len(storedKey) == 32 {
		return storedKey, nil, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}
	if err := saveEncryptionKey(keyPath, key); err != nil {
		return nil, nil, err
	}
	return key, nil, nil
}

func saveEncryptionKey(path string, key []byte) error {
	tmp := path + ".tmp"
	if err := writeSecureFile(tmp, key); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("save encryption key: %w", err)
	}
	return nil
}

func writeSecureFile(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(contents)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func encryptSecret(key []byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return "enc:v1:" + base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func decryptSecret(key []byte, value string) (string, error) {
	if value == "" || !strings.HasPrefix(value, "enc:v1:") {
		return value, nil
	}
	encoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "enc:v1:"))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(encoded) < gcm.NonceSize() {
		return "", errors.New("invalid encrypted credential")
	}
	nonce, ciphertext := encoded[:gcm.NonceSize()], encoded[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func stringField(raw json.RawMessage, field string) string {
	var values map[string]json.RawMessage
	_ = json.Unmarshal(raw, &values)
	var value string
	_ = json.Unmarshal(values[field], &value)
	return value
}

func (s *Store) Channels() []Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Channel, 0, len(s.channels))
	for _, c := range s.channels {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority == out[j].Priority {
			return out[i].ID < out[j].ID
		}
		return out[i].Priority > out[j].Priority
	})
	return out
}

func (s *Store) Channel(id string) (Channel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.channels[id]
	return c, ok
}
func (s *Store) PutChannel(c Channel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, existed := s.channels[c.ID]
	s.channels[c.ID] = c
	if err := s.persistLocked(); err != nil {
		if existed {
			s.channels[c.ID] = old
		} else {
			delete(s.channels, c.ID)
		}
		return err
	}
	return nil
}
func (s *Store) DeleteChannel(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, existed := s.channels[id]
	delete(s.channels, id)
	if err := s.persistLocked(); err != nil {
		if existed {
			s.channels[id] = old
		}
		return err
	}
	return nil
}
func (s *Store) Keys() []Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Key, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
func (s *Store) Key(id string) (Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[id]
	return k, ok
}
func (s *Store) PutKey(k Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, existed := s.keys[k.ID]
	s.keys[k.ID] = k
	if err := s.persistLocked(); err != nil {
		if existed {
			s.keys[k.ID] = old
		} else {
			delete(s.keys, k.ID)
		}
		return err
	}
	return nil
}
func (s *Store) DeleteKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, existed := s.keys[id]
	delete(s.keys, id)
	if err := s.persistLocked(); err != nil {
		if existed {
			s.keys[id] = old
		}
		return err
	}
	return nil
}

func (s *Store) RecordUsage(u Usage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var oldKey Key
	var hadKey bool
	if k, ok := s.keys[u.KeyID]; ok {
		oldKey, hadKey = k, true
		k.UsedTokens += u.PromptTokens + u.CompletionTokens
		s.keys[u.KeyID] = k
	}
	oldUsage := append([]Usage(nil), s.usage...)
	s.usage = append(s.usage, u)
	if len(s.usage) > 10000 {
		s.usage = append([]Usage(nil), s.usage[len(s.usage)-10000:]...)
	}
	if err := s.persistLocked(); err != nil {
		s.usage = oldUsage
		if hadKey {
			s.keys[u.KeyID] = oldKey
		}
		return err
	}
	return nil
}
func (s *Store) Usage(limit int) []Usage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.usage) {
		limit = len(s.usage)
	}
	out := make([]Usage, limit)
	copy(out, s.usage[len(s.usage)-limit:])
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *Store) Authenticate(secret string) (Key, bool) {
	d := digest(secret)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.keys {
		if k.Enabled && equalHex(k.Digest, d) {
			return k, true
		}
	}
	return Key{}, false
}

func NewSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sk-starry-" + hex.EncodeToString(b), nil
}
func digest(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func equalHex(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func NewKey(name string, models []string) (Key, string, error) {
	secret, err := NewSecret()
	if err != nil {
		return Key{}, "", err
	}
	key := Key{ID: newID(), Name: strings.TrimSpace(name), Digest: digest(secret), Prefix: secret[:18], Models: models, Enabled: true, CreatedAt: time.Now().UTC()}
	return key, secret, nil
}
func NewID() string { return newID() }
func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
