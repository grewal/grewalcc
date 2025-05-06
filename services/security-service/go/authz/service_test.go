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
	"github.com/redis/go-redis/v9"
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

type mockRedisClient struct{}

func (m *mockRedisClient) Incr(ctx context.Context, key string) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx); cmd.SetVal(1); return cmd
}
func (m *mockRedisClient) Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd {
	cmd := redis.NewBoolCmd(ctx); cmd.SetVal(true); return cmd
}
func (m *mockRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx); cmd.SetVal("PONG"); return cmd
}
func (m *mockRedisClient) Close() error { return nil }

func TestHandleAuthzRequest(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	testCases := []struct {
		name             string
		mockKV           *mockConsulKV
		mockRedis        *mockRedisClient
		reqMethod        string
		reqPath          string
		reqHeaders       map[string]string
		expectedStatus   int
		expectedHeader   string
		expectedBodyFrag string
	}{
		{
			name:           "Allowed IP, Allowed UA",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0")},
			mockRedis:      &mockRedisClient{},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "GoodAgent/2.0"},
			expectedStatus: http.StatusOK,
			expectedHeader: "Allow",
			expectedBodyFrag: "OK",
		},
		{
			name:           "Blocked IP",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1, 8.8.8.8"), uaData: []byte("BadBot/1.0")},
			mockRedis:      &mockRedisClient{},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "GoodAgent/2.0"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-IPBlock",
			expectedBodyFrag: "Access Denied: IP blocked.",
		},
		{
			name:           "Blocked IP (secondary IP in XFF)",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1, 8.8.8.8"), uaData: []byte("BadBot/1.0")},
			mockRedis:      &mockRedisClient{},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8, 10.0.0.1", "User-Agent": "GoodAgent/2.0"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-IPBlock",
			expectedBodyFrag: "Access Denied: IP blocked.",
		},
		{
			name:           "Blocked UA",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0\nAnotherBadBot")},
			mockRedis:      &mockRedisClient{},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "BadBot/1.0"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-UABlock",
			expectedBodyFrag: "Access Denied: Client blocked.",
		},
		{
			name:           "Blocked UA (second in list)",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0\nAnotherBadBot")},
			mockRedis:      &mockRedisClient{},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "AnotherBadBot"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-UABlock",
			expectedBodyFrag: "Access Denied: Client blocked.",
		},
		{
			name:           "Blocked IP takes precedence over Allowed UA",
			mockKV:         &mockConsulKV{ipData: []byte("8.8.8.8"), uaData: []byte("BadBot/1.0")},
			mockRedis:      &mockRedisClient{},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "GoodAgent/2.0"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-IPBlock",
			expectedBodyFrag: "Access Denied: IP blocked.",
		},
		{
			name:           "Blocked IP takes precedence over Blocked UA",
			mockKV:         &mockConsulKV{ipData: []byte("8.8.8.8"), uaData: []byte("BadBot/1.0")},
			mockRedis:      &mockRedisClient{},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "BadBot/1.0"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-IPBlock",
			expectedBodyFrag: "Access Denied: IP blocked.",
		},
		{
			name:           "Allowed IP, No UA Header",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0")},
			mockRedis:      &mockRedisClient{},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8"},
			expectedStatus: http.StatusOK,
			expectedHeader: "Allow",
			expectedBodyFrag: "OK",
		},
		{
			name:           "No XFF Header, Allowed UA",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0")},
			mockRedis:      &mockRedisClient{},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"User-Agent": "GoodAgent/2.0"},
			expectedStatus: http.StatusOK,
			expectedHeader: "Allow",
			expectedBodyFrag: "OK",
		},
		{
			name:           "No XFF Header, Blocked UA",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0")},
			mockRedis:      &mockRedisClient{},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"User-Agent": "BadBot/1.0"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-UABlock",
			expectedBodyFrag: "Access Denied: Client blocked.",
		},
		{
			name:           "Empty KV lists",
			mockKV:         &mockConsulKV{ipData: []byte(""), uaData: []byte("")},
			mockRedis:      &mockRedisClient{},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "AnyAgent"},
			expectedStatus: http.StatusOK,
			expectedHeader: "Allow",
			expectedBodyFrag: "OK",
		},
		{
			name:           "Nil KV lists (key not found)",
			mockKV:         &mockConsulKV{ipData: nil, uaData: nil},
			mockRedis:      &mockRedisClient{},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "AnyAgent"},
			expectedStatus: http.StatusOK,
			expectedHeader: "Allow",
			expectedBodyFrag: "OK",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app := NewService(logger, tc.mockKV, tc.mockRedis)

			_ = app.FetchAndUpdateIPBlocklist()
			_ = app.FetchAndUpdateUABlocklist()

			req := httptest.NewRequest(tc.reqMethod, tc.reqPath, nil)
			for key, val := range tc.reqHeaders {
				req.Header.Set(key, val)
			}
			rr := httptest.NewRecorder()

			handler := http.HandlerFunc(app.HandleAuthzRequest)
			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tc.expectedStatus)
			}
			if header := rr.Header().Get("X-Authz-Decision"); header != tc.expectedHeader {
				t.Errorf("handler returned wrong X-Authz-Decision header: got %q want %q", header, tc.expectedHeader)
			}
			bodyStr := strings.TrimSpace(rr.Body.String())
			if tc.expectedBodyFrag != "" && !strings.Contains(bodyStr, tc.expectedBodyFrag) {
				t.Errorf("handler returned unexpected body: got %q, does not contain %q", bodyStr, tc.expectedBodyFrag)
			}
		})
	}
}

func TestFetchAndUpdateIPBlocklist(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	testCases := []struct {
		name           string
		mockKV         *mockConsulKV
		mockRedis      *mockRedisClient
		expectedErr    bool
		expectedMapLen int
		expectContains map[string]bool
	}{
		{
			name:           "Successful fetch",
			mockKV:         &mockConsulKV{ipData: []byte(" 1.1.1.1 , 2.2.2.2,3.3.3.3 ")},
			mockRedis:      &mockRedisClient{},
			expectedErr:    false,
			expectedMapLen: 3,
			expectContains: map[string]bool{"1.1.1.1": true, "2.2.2.2": true, "3.3.3.3": true, "4.4.4.4": false},
		},
		{
			name:           "Empty value",
			mockKV:         &mockConsulKV{ipData: []byte("")},
			mockRedis:      &mockRedisClient{},
			expectedErr:    false,
			expectedMapLen: 0,
			expectContains: map[string]bool{"1.1.1.1": false},
		},
		{
			name:           "Key not found",
			mockKV:         &mockConsulKV{ipData: nil},
			mockRedis:      &mockRedisClient{},
			expectedErr:    false,
			expectedMapLen: 0,
			expectContains: map[string]bool{"1.1.1.1": false},
		},
		{
			name:           "Consul error",
			mockKV:         &mockConsulKV{ipError: fmt.Errorf("consul connection error")},
			mockRedis:      &mockRedisClient{},
			expectedErr:    true,
			expectedMapLen: 0,
		},
		{
			name:           "Malformed value (extra commas)",
			mockKV:         &mockConsulKV{ipData: []byte(",1.1.1.1,,2.2.2.2,")},
			mockRedis:      &mockRedisClient{},
			expectedErr:    false,
			expectedMapLen: 2,
			expectContains: map[string]bool{"1.1.1.1": true, "2.2.2.2": true},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app := NewService(logger, tc.mockKV, tc.mockRedis)
			err := app.FetchAndUpdateIPBlocklist()

			if (err != nil) != tc.expectedErr {
				t.Fatalf("FetchAndUpdateIPBlocklist() error = %v, expectedErr %v", err, tc.expectedErr)
			}
			if tc.expectedErr { return }

			app.configMutex.RLock()
			defer app.configMutex.RUnlock()

			if len(app.ipBlocklist) != tc.expectedMapLen {
				t.Errorf("Expected map length %d, got %d", tc.expectedMapLen, len(app.ipBlocklist))
			}
			for key, expected := range tc.expectContains {
				_, actual := app.ipBlocklist[key]
				if actual != expected {
					t.Errorf("For key %q, expected presence %v, got %v", key, expected, actual)
				}
			}
		})
	}
}

func TestFetchAndUpdateUABlocklist(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	testCases := []struct {
		name           string
		mockKV         *mockConsulKV
		mockRedis      *mockRedisClient
		expectedErr    bool
		expectedMapLen int
		expectContains map[string]bool
	}{
		{
			name:           "Successful fetch with newlines",
			mockKV:         &mockConsulKV{uaData: []byte(" BadBot/1.0 \n NastyCrawler/2.1 \n ExactUA String \n")},
			mockRedis:      &mockRedisClient{},
			expectedErr:    false,
			expectedMapLen: 3,
			expectContains: map[string]bool{"BadBot/1.0": true, "NastyCrawler/2.1": true, "ExactUA String": true, "GoodBot": false},
		},
		{
			name:           "Empty value",
			mockKV:         &mockConsulKV{uaData: []byte("")},
			mockRedis:      &mockRedisClient{},
			expectedErr:    false,
			expectedMapLen: 0,
			expectContains: map[string]bool{"BadBot/1.0": false},
		},
		{
			name:           "Key not found",
			mockKV:         &mockConsulKV{uaData: nil},
			mockRedis:      &mockRedisClient{},
			expectedErr:    false,
			expectedMapLen: 0,
			expectContains: map[string]bool{"BadBot/1.0": false},
		},
		{
			name:           "Consul error",
			mockKV:         &mockConsulKV{uaError: fmt.Errorf("consul connection error")},
			mockRedis:      &mockRedisClient{},
			expectedErr:    true,
			expectedMapLen: 0,
		},
		{
			name:           "String with internal commas but no newlines",
			mockKV:         &mockConsulKV{uaData: []byte("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36")},
			mockRedis:      &mockRedisClient{},
			expectedErr:    false,
			expectedMapLen: 1,
			expectContains: map[string]bool{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36": true, "KHTML": false},
		},
		{
			name:           "Value with extra newlines",
			mockKV:         &mockConsulKV{uaData: []byte("\nBadBot/1.0\n\nNastyCrawler/2.1\n")},
			mockRedis:      &mockRedisClient{},
			expectedErr:    false,
			expectedMapLen: 2,
			expectContains: map[string]bool{"BadBot/1.0": true, "NastyCrawler/2.1": true},
		},
		{
			name:           "Single value with newline",
			mockKV:         &mockConsulKV{uaData: []byte("JustOneUA\n")},
			mockRedis:      &mockRedisClient{},
			expectedErr:    false,
			expectedMapLen: 1,
			expectContains: map[string]bool{"JustOneUA": true},
		},
		{
			name:           "Single value no newline",
			mockKV:         &mockConsulKV{uaData: []byte("OnlyMe")},
			mockRedis:      &mockRedisClient{},
			expectedErr:    false,
			expectedMapLen: 1,
			expectContains: map[string]bool{"OnlyMe": true},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app := NewService(logger, tc.mockKV, tc.mockRedis)
			err := app.FetchAndUpdateUABlocklist()

			if (err != nil) != tc.expectedErr {
				t.Fatalf("FetchAndUpdateUABlocklist() error = %v, expectedErr %v", err, tc.expectedErr)
			}
			if tc.expectedErr { return }

			app.configMutex.RLock()
			defer app.configMutex.RUnlock()

			if len(app.userAgentBlocklist) != tc.expectedMapLen {
				t.Errorf("Expected map length %d, got %d (Map: %v)", tc.expectedMapLen, len(app.userAgentBlocklist), app.userAgentBlocklist)
			}
			for key, expected := range tc.expectContains {
				_, actual := app.userAgentBlocklist[key]
				if actual != expected {
					t.Errorf("For key %q, expected presence %v, got %v", key, expected, actual)
				}
			}
		})
	}
}
