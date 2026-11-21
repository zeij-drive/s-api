package server

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/starryapi/starryapi/internal/store"
)

const maxRequestBytes = 10 << 20
const maxResponseBytes = 32 << 20

type Server struct {
	store      *store.Store
	adminToken string
	client     *http.Client
	rrMu       sync.Mutex
	rr         map[string]int
}

func New(st *store.Store, adminToken string) http.Handler {
	s := &Server{store: st, adminToken: adminToken, rr: map[string]int{}, client: &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 30 * time.Second}}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("/admin", s.admin)
	mux.HandleFunc("/admin/", s.admin)
	mux.HandleFunc("/v1/", s.api)
	return recoverer(mux)
}

func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				log.Printf("request panic: %v", v)
				writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	key, ok := s.authenticateKey(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_api_key", "missing or invalid API key")
		return
	}
	if key.QuotaTokens > 0 && key.UsedTokens >= key.QuotaTokens {
		writeError(w, http.StatusTooManyRequests, "quota_exceeded", "API key token quota is exhausted")
		return
	}
	if r.URL.Path == "/v1/models" && r.Method == http.MethodGet {
		s.models(w, key)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is supported for this endpoint")
		return
	}
	if r.ContentLength > maxRequestBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds 10 MiB")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds 10 MiB")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request", "unable to read request body")
		}
		return
	}
	var payload struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || strings.TrimSpace(payload.Model) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "request must contain a model field")
		return
	}
	if len(key.Models) > 0 && !contains(key.Models, payload.Model) && !contains(key.Models, "*") {
		writeError(w, http.StatusForbidden, "model_not_allowed", "API key is not allowed to use this model")
		return
	}
	channels := s.candidates(key.Group, payload.Model)
	if len(channels) == 0 {
		writeError(w, http.StatusBadGateway, "no_channel_available", "no enabled channel supports the requested model")
		return
	}
	s.relay(w, r, key, payload.Model, payload.Stream, body, channels)
}

func (s *Server) authenticateKey(r *http.Request) (store.Key, bool) {
	secret := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if secret == "" {
		return store.Key{}, false
	}
	return s.store.Authenticate(secret)
}

func (s *Server) models(w http.ResponseWriter, key store.Key) {
	set := map[string]bool{}
	for _, c := range s.store.Channels() {
		if !c.Enabled || c.BaseURL == "" || c.APIKey == "" || normalizeGroup(c.Group) != normalizeGroup(key.Group) {
			continue
		}
		for _, model := range c.Models {
			if model != "*" && (len(key.Models) == 0 || contains(key.Models, model) || contains(key.Models, "*")) {
				set[model] = true
			}
		}
		for model := range c.Mapping {
			if (contains(c.Models, model) || contains(c.Models, "*")) && (len(key.Models) == 0 || contains(key.Models, model)) {
				set[model] = true
			}
		}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	data := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		data = append(data, map[string]any{"id": id, "object": "model", "owned_by": "starryapi"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

func (s *Server) candidates(group, model string) []store.Channel {
	var eligible []store.Channel
	for _, c := range s.store.Channels() {
		if c.Enabled && normalizeGroup(c.Group) == normalizeGroup(group) && c.BaseURL != "" && c.APIKey != "" && (contains(c.Models, model) || contains(c.Models, "*")) {
			eligible = append(eligible, c)
		}
	}
	if len(eligible) < 2 {
		return eligible
	}
	// Rotate fairly within each priority tier. Weight gives a channel more slots,
	// while the returned retry list still contains each channel at most once.
	var out []store.Channel
	for i := 0; i < len(eligible); {
		j := i + 1
		for j < len(eligible) && eligible[j].Priority == eligible[i].Priority {
			j++
		}
		tier := eligible[i:j]
		type slot struct{ channel store.Channel }
		var slots []slot
		for _, c := range tier {
			weight := c.Weight
			if weight < 1 {
				weight = 1
			}
			if weight > 100 {
				weight = 100
			}
			for n := 0; n < weight; n++ {
				slots = append(slots, slot{c})
			}
		}
		s.rrMu.Lock()
		rrKey := normalizeGroup(group) + "\x00" + model
		start := s.rr[rrKey] % len(slots)
		s.rr[rrKey] = (start + 1) % len(slots)
		s.rrMu.Unlock()
		seen := map[string]bool{}
		for n := 0; n < len(slots); n++ {
			c := slots[(start+n)%len(slots)].channel
			if !seen[c.ID] {
				out = append(out, c)
				seen[c.ID] = true
			}
		}
		i = j
	}
	return out
}

func (s *Server) relay(w http.ResponseWriter, incoming *http.Request, key store.Key, model string, stream bool, body []byte, channels []store.Channel) {
	var lastErr error
	for i, channel := range channels {
		attemptStart := time.Now()
		upstreamModel := model
		if replacement := channel.Mapping[model]; replacement != "" {
			upstreamModel = replacement
		}
		upstreamBody := body
		if upstreamModel != model {
			upstreamBody = replaceModel(body, upstreamModel)
		}
		target, err := endpoint(channel.BaseURL, incoming.URL)
		if err != nil {
			lastErr = err
			s.record(key, channel, model, upstreamModel, 0, time.Since(attemptStart), err.Error())
			continue
		}
		req, err := http.NewRequestWithContext(incoming.Context(), incoming.Method, target, bytes.NewReader(upstreamBody))
		if err != nil {
			lastErr = err
			s.record(key, channel, model, upstreamModel, 0, time.Since(attemptStart), err.Error())
			continue
		}
		copyRequestHeaders(req.Header, incoming.Header)
		header := channel.AuthHeader
		if header == "" {
			header = "Authorization"
		}
		prefix := channel.AuthPrefix
		if prefix == "" && strings.EqualFold(header, "Authorization") {
			prefix = "Bearer "
		}
		req.Header.Set(header, prefix+channel.APIKey)
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			s.record(key, channel, model, upstreamModel, 0, time.Since(attemptStart), "upstream request failed")
			continue
		}
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && i+1 < len(channels) {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			s.record(key, channel, model, upstreamModel, resp.StatusCode, time.Since(attemptStart), fmt.Sprintf("upstream returned HTTP %d", resp.StatusCode))
			continue
		}
		copyResponseHeaders(w.Header(), resp.Header)
		if stream || strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			w.WriteHeader(resp.StatusCode)
			usage, copyErr := copyEventStream(w, resp.Body)
			resp.Body.Close()
			if copyErr != nil {
				lastErr = copyErr
			}
			s.recordWithUsage(key, channel, model, upstreamModel, resp.StatusCode, time.Since(attemptStart), errorString(copyErr), usage.Prompt, usage.Completion)
			return
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		resp.Body.Close()
		if len(responseBody) > maxResponseBytes {
			readErr = errors.New("upstream response exceeded 32 MiB")
		}
		if readErr != nil {
			lastErr = readErr
			for header := range w.Header() {
				w.Header().Del(header)
			}
			writeError(w, http.StatusBadGateway, "upstream_error", readErr.Error())
			s.recordWithUsage(key, channel, model, upstreamModel, resp.StatusCode, time.Since(attemptStart), readErr.Error(), 0, 0)
			return
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(responseBody)
		usage := parseUsage(responseBody)
		s.recordWithUsage(key, channel, model, upstreamModel, resp.StatusCode, time.Since(attemptStart), errorString(readErr), usage.Prompt, usage.Completion)
		return
	}
	message := "all matching channels failed"
	if lastErr != nil {
		log.Printf("all matching channels failed: %v", lastErr)
	}
	writeError(w, http.StatusBadGateway, "upstream_error", message)
}

type tokenUsage struct {
	Prompt     int64 `json:"prompt_tokens"`
	Completion int64 `json:"completion_tokens"`
}

func parseUsage(body []byte) tokenUsage {
	var v struct {
		Usage tokenUsage `json:"usage"`
	}
	_ = json.Unmarshal(body, &v)
	return v.Usage
}

func copyEventStream(w http.ResponseWriter, body io.Reader) (tokenUsage, error) {
	reader := bufio.NewReaderSize(io.LimitReader(body, maxResponseBytes+1), 64*1024)
	var usage tokenUsage
	var line bytes.Buffer
	var total int64
	for {
		fragment, err := reader.ReadSlice('\n')
		total += int64(len(fragment))
		if total > maxResponseBytes {
			return usage, errors.New("upstream stream exceeded 32 MiB")
		}
		if line.Len()+len(fragment) > maxResponseBytes {
			return usage, errors.New("upstream stream line exceeded 32 MiB")
		}
		_, _ = line.Write(fragment)
		if err == nil || errors.Is(err, io.EOF) {
			if line.Len() > 0 {
				chunk := line.Bytes()
				if _, writeErr := w.Write(chunk); writeErr != nil {
					return usage, writeErr
				}
				if strings.HasPrefix(string(chunk), "data: ") {
					data := strings.TrimSpace(strings.TrimPrefix(string(chunk), "data: "))
					if data != "[DONE]" {
						parsed := parseUsage([]byte(data))
						if parsed.Prompt != 0 || parsed.Completion != 0 {
							usage = parsed
						}
					}
				}
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				line.Reset()
			}
			if errors.Is(err, io.EOF) {
				return usage, nil
			}
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return usage, err
		}
	}
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
func (s *Server) record(key store.Key, channel store.Channel, model, upstream string, status int, latency time.Duration, err string) {
	s.recordWithUsage(key, channel, model, upstream, status, latency, err, 0, 0)
}
func (s *Server) recordWithUsage(key store.Key, channel store.Channel, model, upstream string, status int, latency time.Duration, err string, prompt, completion int64) {
	u := store.Usage{ID: store.NewID(), KeyID: key.ID, ChannelID: channel.ID, Model: model, UpstreamModel: upstream, PromptTokens: prompt, CompletionTokens: completion, StatusCode: status, LatencyMS: latency.Milliseconds(), Error: err, CreatedAt: time.Now().UTC()}
	if e := s.store.RecordUsage(u); e != nil {
		log.Printf("record usage: %v", e)
	}
}

func endpoint(base string, incoming *url.URL) (string, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("invalid channel base_url")
	}
	basePath := strings.TrimRight(u.Path, "/")
	requestPath := incoming.Path
	if strings.HasSuffix(basePath, "/v1") && (requestPath == "/v1" || strings.HasPrefix(requestPath, "/v1/")) {
		requestPath = strings.TrimPrefix(requestPath, "/v1")
	}
	u.Path = basePath + requestPath
	u.RawPath = ""
	query := u.Query()
	for key, values := range incoming.Query() {
		query.Del(key)
		for _, value := range values {
			query.Add(key, value)
		}
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func replaceModel(body []byte, model string) []byte {
	var v map[string]json.RawMessage
	if json.Unmarshal(body, &v) != nil {
		return body
	}
	b, _ := json.Marshal(model)
	v["model"] = b
	out, err := json.Marshal(v)
	if err != nil {
		return body
	}
	return out
}
func copyRequestHeaders(dst, src http.Header) {
	for _, h := range []string{"Content-Type", "Accept", "OpenAI-Beta", "OpenAI-Organization", "User-Agent"} {
		if v := src.Values(h); len(v) > 0 {
			dst[h] = append([]string(nil), v...)
		}
	}
}
func copyResponseHeaders(dst, src http.Header) {
	for k, values := range src {
		lk := strings.ToLower(k)
		if lk == "connection" || lk == "transfer-encoding" || lk == "content-length" || lk == "keep-alive" || lk == "proxy-authenticate" || lk == "proxy-authorization" || lk == "te" || lk == "trailer" || lk == "upgrade" {
			continue
		}
		dst[k] = append([]string(nil), values...)
	}
}
func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	if !authorizedAdmin(r, s.adminToken) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "valid admin bearer token required")
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin"), "/")
	parts := strings.Split(path, "/")
	if path == "" {
		writeJSON(w, http.StatusOK, map[string]any{"service": "StarryAPI", "api": "/v1", "admin": "/admin"})
		return
	}
	switch parts[0] {
	case "channels":
		s.adminChannels(w, r, parts)
	case "keys":
		s.adminKeys(w, r, parts)
	case "usage":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		limit := 100
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
				limit = n
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": s.store.Usage(limit)})
	default:
		writeError(w, http.StatusNotFound, "not_found", "admin endpoint not found")
	}
}

func authorizedAdmin(r *http.Request, expected string) bool {
	got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	return got != "" && len(got) == len(expected) && subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

type channelInput struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	BaseURL    string            `json:"base_url"`
	APIKey     string            `json:"api_key"`
	AuthHeader string            `json:"auth_header"`
	AuthPrefix string            `json:"auth_prefix"`
	Group      string            `json:"group"`
	Models     []string          `json:"models"`
	Mapping    map[string]string `json:"model_mapping"`
	Priority   int               `json:"priority"`
	Weight     int               `json:"weight"`
	Enabled    *bool             `json:"enabled"`
}

func (s *Server) adminChannels(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			out := s.store.Channels()
			for i := range out {
				out[i].APIKey = ""
			}
			writeJSON(w, http.StatusOK, map[string]any{"data": out})
		case http.MethodPost:
			var in channelInput
			if !decodeJSON(w, r, &in) {
				return
			}
			if err := validateChannel(in); err != nil {
				writeError(w, http.StatusBadRequest, "invalid_channel", err.Error())
				return
			}
			enabled := true
			if in.Enabled != nil {
				enabled = *in.Enabled
			}
			c := store.Channel{ID: store.NewID(), Name: strings.TrimSpace(in.Name), Type: channelType(in.Type), BaseURL: strings.TrimRight(in.BaseURL, "/"), APIKey: in.APIKey, AuthHeader: in.AuthHeader, AuthPrefix: in.AuthPrefix, Group: normalizeGroup(in.Group), Models: in.Models, Mapping: in.Mapping, Priority: in.Priority, Weight: in.Weight, Enabled: enabled, CreatedAt: time.Now().UTC()}
			if err := s.store.PutChannel(c); err != nil {
				writeError(w, 500, "storage_error", "could not persist channel")
				return
			}
			c.APIKey = ""
			writeJSON(w, http.StatusCreated, c)
		default:
			methodNotAllowed(w)
		}
		return
	}
	id := parts[1]
	current, ok := s.store.Channel(id)
	if !ok {
		writeError(w, 404, "not_found", "channel not found")
		return
	}
	if len(parts) == 3 && parts[2] == "test" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		s.testChannel(w, r, current)
		return
	}
	if len(parts) != 2 {
		writeError(w, 404, "not_found", "admin endpoint not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		current.APIKey = ""
		writeJSON(w, 200, current)
	case http.MethodDelete:
		if err := s.store.DeleteChannel(id); err != nil {
			writeError(w, 500, "storage_error", "could not delete channel")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPatch:
		var in struct {
			Name       *string            `json:"name"`
			Type       *string            `json:"type"`
			BaseURL    *string            `json:"base_url"`
			APIKey     *string            `json:"api_key"`
			AuthHeader *string            `json:"auth_header"`
			AuthPrefix *string            `json:"auth_prefix"`
			Group      *string            `json:"group"`
			Models     *[]string          `json:"models"`
			Mapping    *map[string]string `json:"model_mapping"`
			Priority   *int               `json:"priority"`
			Weight     *int               `json:"weight"`
			Enabled    *bool              `json:"enabled"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		if in.Name != nil {
			current.Name = strings.TrimSpace(*in.Name)
		}
		if in.Type != nil {
			current.Type = channelType(*in.Type)
		}
		if in.BaseURL != nil {
			current.BaseURL = strings.TrimRight(*in.BaseURL, "/")
		}
		if in.APIKey != nil {
			current.APIKey = *in.APIKey
		}
		if in.AuthHeader != nil {
			current.AuthHeader = *in.AuthHeader
		}
		if in.AuthPrefix != nil {
			current.AuthPrefix = *in.AuthPrefix
		}
		if in.Group != nil {
			current.Group = normalizeGroup(*in.Group)
		}
		if in.Models != nil {
			current.Models = *in.Models
		}
		if in.Mapping != nil {
			current.Mapping = *in.Mapping
		}
		if in.Priority != nil {
			current.Priority = *in.Priority
		}
		if in.Weight != nil {
			current.Weight = *in.Weight
		}
		if in.Enabled != nil {
			current.Enabled = *in.Enabled
		}
		if err := validateChannel(channelInput{Name: current.Name, Type: current.Type, BaseURL: current.BaseURL, APIKey: current.APIKey, AuthHeader: current.AuthHeader, AuthPrefix: current.AuthPrefix, Group: current.Group, Models: current.Models, Priority: current.Priority, Weight: current.Weight}); err != nil {
			writeError(w, 400, "invalid_channel", err.Error())
			return
		}
		if err := s.store.PutChannel(current); err != nil {
			writeError(w, 500, "storage_error", "could not persist channel")
			return
		}
		current.APIKey = ""
		writeJSON(w, 200, current)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) testChannel(w http.ResponseWriter, r *http.Request, c store.Channel) {
	target, err := endpoint(c.BaseURL, &url.URL{Path: "/v1/models"})
	if err != nil {
		writeError(w, 400, "invalid_channel", err.Error())
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		writeError(w, 400, "invalid_channel", "could not create test request")
		return
	}
	header := c.AuthHeader
	if header == "" {
		header = "Authorization"
	}
	prefix := c.AuthPrefix
	if prefix == "" && strings.EqualFold(header, "Authorization") {
		prefix = "Bearer "
	}
	req.Header.Set(header, prefix+c.APIKey)
	resp, err := s.client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": truncate(err.Error(), 500)})
		return
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "failed to read provider response"})
		return
	}
	var data any
	if json.Unmarshal(body, &data) != nil {
		data = map[string]string{"body": truncate(string(body), 512)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": resp.StatusCode >= 200 && resp.StatusCode < 300, "upstream_status": resp.StatusCode, "response": data})
}

func validateChannel(c channelInput) error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("name is required")
	}
	if channelType(c.Type) != "openai" {
		return errors.New("this build supports the openai-compatible channel type")
	}
	if strings.TrimSpace(c.APIKey) == "" {
		return errors.New("api_key is required")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("base_url must be an absolute http(s) URL without embedded credentials")
	}
	if len(c.Models) == 0 {
		return errors.New("models must contain at least one model ID or *")
	}
	for _, model := range c.Models {
		if strings.TrimSpace(model) == "" {
			return errors.New("models cannot contain empty values")
		}
	}
	for publicModel, upstreamModel := range c.Mapping {
		if strings.TrimSpace(publicModel) == "" || strings.TrimSpace(upstreamModel) == "" {
			return errors.New("model_mapping cannot contain empty names or targets")
		}
		if !contains(c.Models, publicModel) && !contains(c.Models, "*") {
			return fmt.Errorf("model_mapping key %q must also appear in models", publicModel)
		}
	}
	if c.Weight < 0 {
		return errors.New("weight cannot be negative")
	}
	if c.AuthHeader != "" && (strings.ContainsAny(c.AuthHeader, "\r\n:") || strings.TrimSpace(c.AuthHeader) != c.AuthHeader) {
		return errors.New("invalid auth_header")
	}
	if c.AuthHeader != "" && !validHeaderName(c.AuthHeader) {
		return errors.New("invalid auth_header")
	}
	if strings.ContainsAny(c.AuthPrefix, "\r\n") {
		return errors.New("invalid auth_prefix")
	}
	return nil
}
func channelType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" || t == "openai-compatible" {
		return "openai"
	}
	return t
}

func normalizeGroup(group string) string {
	group = strings.TrimSpace(group)
	if group == "" {
		return "default"
	}
	return group
}

func (s *Server) adminKeys(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			keys := s.store.Keys()
			for i := range keys {
				keys[i].Digest = ""
			}
			writeJSON(w, 200, map[string]any{"data": keys})
		case http.MethodPost:
			var in struct {
				Name   string   `json:"name"`
				Models []string `json:"models"`
				Group  string   `json:"group"`
			}
			if !decodeJSON(w, r, &in) {
				return
			}
			if strings.TrimSpace(in.Name) == "" {
				writeError(w, 400, "invalid_key", "name is required")
				return
			}
			k, secret, err := store.NewKey(in.Name, in.Models)
			if err != nil {
				writeError(w, 500, "key_generation_failed", "could not generate API key")
				return
			}
			k.Group = normalizeGroup(in.Group)
			if err := s.store.PutKey(k); err != nil {
				writeError(w, 500, "storage_error", "could not persist API key")
				return
			}
			k.Digest = ""
			writeJSON(w, 201, map[string]any{"key": k, "secret": secret})
		default:
			methodNotAllowed(w)
		}
		return
	}
	id := parts[1]
	current, ok := s.store.Key(id)
	if !ok {
		writeError(w, 404, "not_found", "API key not found")
		return
	}
	if len(parts) != 2 {
		writeError(w, 404, "not_found", "admin endpoint not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		current.Digest = ""
		writeJSON(w, 200, current)
	case http.MethodDelete:
		if err := s.store.DeleteKey(id); err != nil {
			writeError(w, 500, "storage_error", "could not delete API key")
			return
		}
		w.WriteHeader(204)
	case http.MethodPatch:
		var in struct {
			Name        *string   `json:"name"`
			Models      *[]string `json:"models"`
			Enabled     *bool     `json:"enabled"`
			QuotaTokens *int64    `json:"quota_tokens"`
			Group       *string   `json:"group"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		if in.Name != nil {
			current.Name = *in.Name
		}
		if in.Models != nil {
			current.Models = *in.Models
		}
		if in.Enabled != nil {
			current.Enabled = *in.Enabled
		}
		if in.QuotaTokens != nil {
			current.QuotaTokens = *in.QuotaTokens
		}
		if in.Group != nil {
			current.Group = normalizeGroup(*in.Group)
		}
		if current.QuotaTokens < 0 {
			writeError(w, 400, "invalid_key", "quota_tokens cannot be negative")
			return
		}
		if strings.TrimSpace(current.Name) == "" {
			writeError(w, 400, "invalid_key", "name is required")
			return
		}
		if err := s.store.PutKey(current); err != nil {
			writeError(w, 500, "storage_error", "could not persist API key")
			return
		}
		current.Digest = ""
		writeJSON(w, 200, current)
	default:
		methodNotAllowed(w)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.ContentLength > 1<<20 {
		writeError(w, 413, "request_too_large", "request body exceeds 1 MiB")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeDecodeError(w, err)
		return false
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeDecodeError(w, err)
		return false
	}
	return true
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds 1 MiB")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid_json", "invalid JSON request body")
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range []byte(name) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	return true
}
func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, 405, "method_not_allowed", "method not allowed")
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"type": code, "message": message}})
}
