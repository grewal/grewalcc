package authz

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	consulapi "github.com/hashicorp/consul/api"
	// REMOVED "github.com/redis/go-redis/v9" import
)

type mockConsulKV struct {
	ipData  []byte
	ipError error
	uaData  []byte
	uaError error
}

func (m *mockConsulKV) Get(key string, q *consulapi.QueryOptions) (*consulapi.KVPair, *consulapi.QueryMeta, error) {
	switch key {
	case ipBlocklistKVKey:
		if m.ipError != nil { return nil, nil, m.ipError }
		if m.ipData == nil { return nil, nil, nil }
		return &consulapi.KVPair{Key: key, Value: m.ipData}, nil, nil
	case uaBlocklistKVKey:
		if m.uaError != nil { return nil, nil, m.uaError }
		if m.uaData == nil { return nil, nil, nil }
		return &consulapi.KVPair{Key: key, Value: m.uaData}, nil, nil
	default:
		return nil, nil, nil
	}
}

func TestHandleAuthzRequest(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	testLimit := int64(1); testWindow := 5 * time.Second
	testCases := []struct {
		name             string
		mockKV           *mockConsulKV
		rateLimitEnabled bool
		rateLimitCount   int64
		rateLimitWindow  time.Duration
		reqMethod        string
		reqPath          string
		reqHeaders       map[string]string
		expectedStatus   int
		expectedHeader   string
		expectedBodyFrag string
	}{
		{ name: "Allowed IP, Allowed UA, RL Disabled", mockKV: &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0")}, rateLimitEnabled: false, rateLimitCount: testLimit, rateLimitWindow: testWindow, reqMethod: http.MethodGet, reqPath: "/", reqHeaders: map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "GoodAgent/2.0"}, expectedStatus: http.StatusOK, expectedHeader: "Allow", expectedBodyFrag: "OK", },
		{ name: "Blocked IP, RL Disabled", mockKV: &mockConsulKV{ipData: []byte("1.1.1.1, 8.8.8.8"), uaData: []byte("BadBot/1.0")}, rateLimitEnabled: false, rateLimitCount: testLimit, rateLimitWindow: testWindow, reqMethod: http.MethodGet, reqPath: "/", reqHeaders: map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "GoodAgent/2.0"}, expectedStatus: http.StatusForbidden, expectedHeader: "Deny-IPBlock", expectedBodyFrag: "Access Denied: IP blocked.", },
		{ name: "Blocked UA, RL Disabled", mockKV: &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0\nAnotherBadBot")}, rateLimitEnabled: false, rateLimitCount: testLimit, rateLimitWindow: testWindow, reqMethod: http.MethodGet, reqPath: "/", reqHeaders: map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "BadBot/1.0"}, expectedStatus: http.StatusForbidden, expectedHeader: "Deny-UABlock", expectedBodyFrag: "Access Denied: Client blocked.", },
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app := NewService(logger, tc.mockKV, nil)
			app.rateLimitEnabled = tc.rateLimitEnabled; app.rateLimitCount = tc.rateLimitCount; app.rateLimitWindow = tc.rateLimitWindow
			_ = app.FetchAndUpdateIPBlocklist(); _ = app.FetchAndUpdateUABlocklist()
			req := httptest.NewRequest(tc.reqMethod, tc.reqPath, nil); for key, val := range tc.reqHeaders { req.Header.Set(key, val) }; req = req.WithContext(context.Background()); rr := httptest.NewRecorder()
			handler := http.HandlerFunc(app.HandleAuthzRequest); handler.ServeHTTP(rr, req)
			if status := rr.Code; status != tc.expectedStatus { t.Errorf("handler returned wrong status code: got %v want %v", status, tc.expectedStatus) }
			if header := rr.Header().Get("X-Authz-Decision"); header != tc.expectedHeader { t.Errorf("handler returned wrong X-Authz-Decision header: got %q want %q", header, tc.expectedHeader) }
			bodyStr := strings.TrimSpace(rr.Body.String()); if tc.expectedBodyFrag != "" && !strings.Contains(bodyStr, tc.expectedBodyFrag) { t.Errorf("handler returned unexpected body: got %q, does not contain %q", bodyStr, tc.expectedBodyFrag) }
			if tc.expectedStatus == http.StatusTooManyRequests { if retryAfter := rr.Header().Get("Retry-After"); retryAfter == "" { t.Errorf("handler did not return Retry-After header on 429 status") } }
		})
	}
}

func TestFetchAndUpdateIPBlocklist(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	testCases := []struct { name string; mockKV *mockConsulKV; expectedErr bool; expectedMapLen int; expectContains map[string]bool }{
		{ name: "Successful fetch", mockKV: &mockConsulKV{ipData: []byte(" 1.1.1.1 , 2.2.2.2,3.3.3.3 ")}, expectedErr: false, expectedMapLen: 3, expectContains: map[string]bool{"1.1.1.1": true, "2.2.2.2": true, "3.3.3.3": true, "4.4.4.4": false}},
		{ name: "Consul error", mockKV: &mockConsulKV{ipError: fmt.Errorf("consul connection error")}, expectedErr: true, expectedMapLen: 0},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app := NewService(logger, tc.mockKV, nil)
			err := app.FetchAndUpdateIPBlocklist()
            if (err != nil) != tc.expectedErr { t.Fatalf("FetchAndUpdateIPBlocklist() error = %v, expectedErr %v", err, tc.expectedErr) }
            if tc.expectedErr { return }
            app.configMutex.RLock(); defer app.configMutex.RUnlock()
            if len(app.ipBlocklist) != tc.expectedMapLen { t.Errorf("Expected map length %d, got %d", tc.expectedMapLen, len(app.ipBlocklist)) }
            for key, expected := range tc.expectContains { if _, actual := app.ipBlocklist[key]; actual != expected { t.Errorf("For key %q, expected presence %v, got %v", key, expected, actual) } }
		})
	}
}

func TestFetchAndUpdateUABlocklist(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	testCases := []struct { name string; mockKV *mockConsulKV; expectedErr bool; expectedMapLen int; expectContains map[string]bool }{
		{ name: "Successful fetch with newlines", mockKV: &mockConsulKV{uaData: []byte(" BadBot/1.0 \n NastyCrawler/2.1 \n ExactUA String \n")}, expectedErr: false, expectedMapLen: 3, expectContains: map[string]bool{"BadBot/1.0": true, "NastyCrawler/2.1": true, "ExactUA String": true, "GoodBot": false}},
		{ name: "Consul error", mockKV: &mockConsulKV{uaError: fmt.Errorf("consul connection error")}, expectedErr: true, expectedMapLen: 0},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app := NewService(logger, tc.mockKV, nil)
			err := app.FetchAndUpdateUABlocklist()
            if (err != nil) != tc.expectedErr { t.Fatalf("FetchAndUpdateUABlocklist() error = %v, expectedErr %v", err, tc.expectedErr) }
            if tc.expectedErr { return }
            app.configMutex.RLock(); defer app.configMutex.RUnlock()
            if len(app.userAgentBlocklist) != tc.expectedMapLen { t.Errorf("Expected map length %d, got %d (Map: %v)", tc.expectedMapLen, len(app.userAgentBlocklist), app.userAgentBlocklist) }
            for key, expected := range tc.expectContains { if _, actual := app.userAgentBlocklist[key]; actual != expected { t.Errorf("For key %q, expected presence %v, got %v", key, expected, actual) } }
		})
	}
}
