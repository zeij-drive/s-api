package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/starryapi/starryapi/internal/store"
)

func TestChatCompletionRoutesModelAndRecordsUsage(t *testing.T) {
	var gotPath, gotAuth, gotModel string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode upstream body: %v", err)
		}
		gotModel, _ = body["model"].(string)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"cmpl_test","object":"chat.completion","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2}}`)
	}))
	defer provider.Close()

	st, key, secret := setupStore(t)
	channel := store.Channel{ID: "c1", Name: "test", Type: "openai", BaseURL: provider.URL + "/v1", APIKey: "provider-secret", Models: []string{"public-model"}, Mapping: map[string]string{"public-model": "upstream-model"}, Enabled: true, Weight: 1}
	if err := st.PutChannel(channel); err != nil {
		t.Fatal(err)
	}
	h := New(st, "admin-secret")
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"public-model","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if gotPath != "/v1/chat/completions" || gotAuth != "Bearer provider-secret" || gotModel != "upstream-model" {
		t.Fatalf("upstream path/auth/model = %q/%q/%q", gotPath, gotAuth, gotModel)
	}
	updated, ok := st.Key(key.ID)
	if !ok {
		t.Fatal("API key disappeared")
	}
	if updated.UsedTokens != 5 {
		t.Fatalf("used_tokens=%d, want 5", updated.UsedTokens)
	}
	logs := st.Usage(10)
	if len(logs) != 1 || logs[0].PromptTokens != 3 || logs[0].CompletionTokens != 2 {
		t.Fatalf("usage logs=%+v", logs)
	}
}

func TestChatCompletionRetriesNextChannel(t *testing.T) {
	failures := 0
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		failures++
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"error":"busy"}`)
	}))
	defer failing.Close()
	success := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	defer success.Close()
	st, _, secret := setupStore(t)
	for _, c := range []store.Channel{
		{ID: "high", Name: "first", BaseURL: failing.URL, APIKey: "a", Models: []string{"m"}, Priority: 10, Enabled: true},
		{ID: "low", Name: "fallback", BaseURL: success.URL, APIKey: "b", Models: []string{"m"}, Priority: 1, Enabled: true},
	} {
		if err := st.PutChannel(c); err != nil {
			t.Fatal(err)
		}
	}
	h := New(st, "admin-secret")
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if failures != 1 {
		t.Fatalf("primary channel attempts=%d, want 1", failures)
	}
	logs := st.Usage(10)
	if len(logs) != 2 || logs[0].StatusCode != http.StatusOK || logs[1].StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("usage log order/status: %+v", logs)
	}
}

func TestStreamingPassesSSEAndRecordsUsageChunk(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":4}}\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer provider.Close()
	st, key, secret := setupStore(t)
	if err := st.PutChannel(store.Channel{ID: "stream", Name: "stream", BaseURL: provider.URL, APIKey: "upstream", Models: []string{"m"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m","stream":true,"messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	New(st, "admin-secret").ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "data: [DONE]") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	updated, ok := st.Key(key.ID)
	if !ok || updated.UsedTokens != 11 {
		t.Fatalf("key=%+v, found=%v", updated, ok)
	}
}

func TestQuotaStopsCallsAfterRecordedTokenUsage(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	defer provider.Close()
	st, key, secret := setupStore(t)
	key.QuotaTokens = 1
	if err := st.PutKey(key); err != nil {
		t.Fatal(err)
	}
	if err := st.PutChannel(store.Channel{ID: "quota", Name: "quota", BaseURL: provider.URL, APIKey: "upstream", Models: []string{"m"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	h := New(st, "admin-secret")
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[]}`))
		req.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if first := call(); first.Code != http.StatusOK {
		t.Fatalf("first request status=%d body=%s", first.Code, first.Body.String())
	}
	if second := call(); second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status=%d body=%s", second.Code, second.Body.String())
	}
}

func TestEndpointJoinsVersionPath(t *testing.T) {
	got, err := endpoint("https://provider.example/v1", mustURL("/v1/chat/completions?x=1"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://provider.example/v1/chat/completions?x=1" {
		t.Fatalf("endpoint=%q", got)
	}
}

func TestEndpointPreservesBaseQueryAndMergesRequestQuery(t *testing.T) {
	got, err := endpoint("https://provider.example/v1?api-version=2026-01-01&x=base", mustURL("/v1/models?x=request&limit=2"))
	if err != nil {
		t.Fatal(err)
	}
	parsed := mustURL(got)
	query := parsed.Query()
	if parsed.Path != "/v1/models" || query.Get("api-version") != "2026-01-01" || query.Get("x") != "request" || query.Get("limit") != "2" {
		t.Fatalf("endpoint=%q", got)
	}
}

func TestUserKeyOnlyRoutesWithinItsGroup(t *testing.T) {
	called := ""
	providerA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = "group-a"; io.WriteString(w, `{"choices":[]}`) }))
	defer providerA.Close()
	providerB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = "group-b"; io.WriteString(w, `{"choices":[]}`) }))
	defer providerB.Close()
	st, key, secret := setupStore(t)
	key.Group = "group-a"
	if err := st.PutKey(key); err != nil {
		t.Fatal(err)
	}
	for _, c := range []store.Channel{
		{ID: "a", Name: "A", BaseURL: providerA.URL, APIKey: "a-key", Models: []string{"m"}, Group: "group-a", Enabled: true},
		{ID: "b", Name: "B", BaseURL: providerB.URL, APIKey: "b-key", Models: []string{"m"}, Group: "group-b", Enabled: true},
	} {
		if err := st.PutChannel(c); err != nil {
			t.Fatal(err)
		}
	}
	h := New(st, "admin-secret")
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || called != "group-a" {
		t.Fatalf("status=%d provider=%q body=%s", w.Code, called, w.Body.String())
	}
}

func TestUnauthorizedKeyAndAdminRequestsAreRejected(t *testing.T) {
	st, _, _ := setupStore(t)
	h := New(st, "admin-secret")
	for _, path := range []string{"/v1/models", "/admin/channels"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s status=%d, want 401", path, w.Code)
		}
	}
}

func TestAdminCreationAcceptsCompatibleTypeAndRedactsProviderKey(t *testing.T) {
	st, _, _ := setupStore(t)
	h := New(st, "admin-secret")
	body := `{"name":"provider","type":"openai-compatible","base_url":"https://provider.example/v1","api_key":"private-provider-key","models":["m"]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/channels", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private-provider-key") {
		t.Fatal("channel response leaked provider API key")
	}
	channels := st.Channels()
	if len(channels) != 1 || channels[0].Type != "openai" || channels[0].APIKey != "private-provider-key" {
		t.Fatalf("created channel=%+v", channels)
	}
}

func setupStore(t *testing.T) (*store.Store, store.Key, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	k, secret, err := store.NewKey("test key", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutKey(k); err != nil {
		t.Fatal(err)
	}
	return st, k, secret
}

func mustURL(path string) *url.URL {
	u, err := url.Parse(path)
	if err != nil {
		panic(err)
	}
	return u
}
