package store

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChannelCredentialEncryptedAtRestAndRestored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	channel := Channel{ID: "channel-1", Name: "provider", APIKey: "very-secret-upstream-token", Models: []string{"model"}, Enabled: true}
	if err := st.PutChannel(channel); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), channel.APIKey) {
		t.Fatal("upstream credential was persisted as plaintext")
	}
	if !strings.Contains(string(contents), "enc:v1:") {
		t.Fatal("encrypted credential marker not found")
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok := reopened.Channel(channel.ID)
	if !ok || loaded.APIKey != channel.APIKey {
		t.Fatalf("reloaded API key=%q, found=%v", loaded.APIKey, ok)
	}
}

func TestOpenMigratesPlaintextChannelCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	plaintext := `{"channels":{"old":{"id":"old","name":"old","api_key":"legacy-secret","models":["m"],"enabled":true}},"keys":{}}`
	if err := os.WriteFile(path, []byte(plaintext), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok := st.Channel("old")
	if !ok || loaded.APIKey != "legacy-secret" {
		t.Fatalf("migrated API key=%q, found=%v", loaded.APIKey, ok)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "legacy-secret") || !strings.Contains(string(contents), "enc:v1:") {
		t.Fatal("legacy credential was not encrypted during migration")
	}
}

func TestMasterKeyCanReplaceGeneratedKeyWithoutLosingCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	channel := Channel{ID: "channel-1", Name: "provider", APIKey: "credential-to-keep", Models: []string{"m"}, Enabled: true}
	if err := st.PutChannel(channel); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MASTER_KEY", strings.Repeat("ab", 32))
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok := reopened.Channel(channel.ID)
	if !ok || loaded.APIKey != channel.APIKey {
		t.Fatalf("reloaded channel=%+v, found=%v", loaded, ok)
	}
	storedKey, err := os.ReadFile(path + ".key")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedKey, bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatal("master key was not persisted for the next startup")
	}
}
