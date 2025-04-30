package authz

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	// "sync" // No longer needed here
	"testing"

	consulapi "github.com/hashicorp/consul/api"
)

// mockConsulKV provides a mock implementation of the consulKV interface for testing.
type mockConsulKV struct {
	// Values to return for IP blocklist key
	ipData  []byte
	ipError error
	// Values to return for UA blocklist key
	uaData  []byte
	uaError error
}

// Get simulates the Consul KV Get operation.
func (m *mockConsulKV) Get(key string, q *consulapi.QueryOptions) (*consulapi.KVPair, *consulapi.QueryMeta, error) {
	switch key {
	case ipBlocklistKVKey:
		if m.ipError != nil {
			return nil, nil, m.ipError
		}
		if m.ipData == nil { // Simulate key not found
			return nil, nil, nil // No error, but nil pair
		}
		return &consulapi.KVPair{Key: key, Value: m.ipData}, nil, nil
	case uaBlocklistKVKey:
		if m.uaError != nil {
			return nil, nil, m.uaError
		}
		if m.uaData == nil { // Simulate key not found
			return nil, nil, nil // No error, but nil pair
		}
		return &consulapi.KVPair{Key: key, Value: m.uaData}, nil, nil
	default:
		return nil, nil, fmt.Errorf("mock unexpected key: %s", key)
	}
}

// --- Test HandleAuthzRequest ---

func TestHandleAuthzRequest(t *testing.T) {
	// Shared logger for tests
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})) // Log debug for tests

	testCases := []struct {
		name             string
		mockKV           *mockConsulKV // Define KV state per test case
		reqMethod        string        // Request method (e.g., GET)
		reqPath          string        // Request path (e.g., /)
		reqHeaders       map[string]string
		expectedStatus   int
		expectedHeader   string // Expected value for X-Authz-Decision
		expectedBodyFrag string // Optional: fragment expected in body for denials
	}{
		{
			name:           "Allowed IP, Allowed UA",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0")},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "GoodAgent/2.0"},
			expectedStatus: http.StatusOK,
			expectedHeader: "Allow",
		},
		{
			name:           "Blocked IP",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1, 8.8.8.8"), uaData: []byte("BadBot/1.0")},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "GoodAgent/2.0"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-IPBlock",
			expectedBodyFrag: "Access denied",
		},
		{
			name:           "Blocked IP (secondary IP in XFF)",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1, 8.8.8.8"), uaData: []byte("BadBot/1.0")},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8, 10.0.0.1", "User-Agent": "GoodAgent/2.0"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-IPBlock",
			expectedBodyFrag: "Access denied",
		},
		{
			name:           "Blocked UA",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0, AnotherBadBot")},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "BadBot/1.0"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-UABlock",
			expectedBodyFrag: "Access denied",
		},
		{
			name:           "Blocked UA (second in list)",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0, AnotherBadBot")},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "AnotherBadBot"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-UABlock",
			expectedBodyFrag: "Access denied",
		},
		{
			name:           "Blocked IP takes precedence over Allowed UA",
			mockKV:         &mockConsulKV{ipData: []byte("8.8.8.8"), uaData: []byte("BadBot/1.0")},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "GoodAgent/2.0"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-IPBlock", // IP checked first
			expectedBodyFrag: "Access denied",
		},
		{
			name:           "Blocked IP takes precedence over Blocked UA",
			mockKV:         &mockConsulKV{ipData: []byte("8.8.8.8"), uaData: []byte("BadBot/1.0")},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "BadBot/1.0"},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-IPBlock", // IP checked first
			expectedBodyFrag: "Access denied",
		},
		{
			name:           "Allowed IP, No UA Header",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0")},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8"}, // No User-Agent
			expectedStatus: http.StatusOK,
			expectedHeader: "Allow",
		},
		{
			name:           "No XFF Header, Allowed UA",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0")},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"User-Agent": "GoodAgent/2.0"}, // No XFF
			expectedStatus: http.StatusOK,
			expectedHeader: "Allow",
		},
		{
			name:           "No XFF Header, Blocked UA",
			mockKV:         &mockConsulKV{ipData: []byte("1.1.1.1"), uaData: []byte("BadBot/1.0")},
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"User-Agent": "BadBot/1.0"}, // No XFF
			expectedStatus: http.StatusForbidden,
			expectedHeader: "Deny-UABlock",
			expectedBodyFrag: "Access denied",
		},
		{
			name:           "Empty KV lists",
			mockKV:         &mockConsulKV{ipData: []byte(""), uaData: []byte("")}, // Empty values
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "AnyAgent"},
			expectedStatus: http.StatusOK,
			expectedHeader: "Allow",
		},
		{
			name:           "Nil KV lists (key not found)",
			mockKV:         &mockConsulKV{ipData: nil, uaData: nil}, // nil simulates key not found
			reqMethod:      http.MethodGet,
			reqPath:        "/",
			reqHeaders:     map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "AnyAgent"},
			expectedStatus: http.StatusOK,
			expectedHeader: "Allow",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new service instance for each test case with its specific mock KV
			app := NewService(logger, tc.mockKV)

			// Need to manually trigger the fetch to populate the maps for the test
			err := app.FetchAndUpdateIPBlocklist()
			if err != nil {
				// Log if the mock itself had an error configured, otherwise it's unexpected
				if tc.mockKV.ipError == nil {
					t.Fatalf("Unexpected error during initial IP fetch for test setup: %v", err)
				}
			}
			err = app.FetchAndUpdateUABlocklist()
			if err != nil {
				if tc.mockKV.uaError == nil {
					t.Fatalf("Unexpected error during initial UA fetch for test setup: %v", err)
				}
			}

			// Create request and response recorder
			// Use tc.reqMethod and tc.reqPath now
			req := httptest.NewRequest(tc.reqMethod, tc.reqPath, nil)
			for key, val := range tc.reqHeaders {
				req.Header.Set(key, val)
			}
			rr := httptest.NewRecorder()

			// Execute the handler
			handler := http.HandlerFunc(app.HandleAuthzRequest)
			handler.ServeHTTP(rr, req)

			// Assertions
			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tc.expectedStatus)
			}

			if header := rr.Header().Get("X-Authz-Decision"); header != tc.expectedHeader {
				t.Errorf("handler returned wrong X-Authz-Decision header: got %q want %q", header, tc.expectedHeader)
			}

			if tc.expectedBodyFrag != "" {
				if !bytes.Contains(rr.Body.Bytes(), []byte(tc.expectedBodyFrag)) {
					t.Errorf("handler returned unexpected body: got %q, does not contain %q", rr.Body.String(), tc.expectedBodyFrag)
				}
			}
		})
	}
}

// --- Test FetchAndUpdateIPBlocklist ---

func TestFetchAndUpdateIPBlocklist(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	testCases := []struct {
		name           string
		mockKV         *mockConsulKV
		expectedErr    bool
		expectedMapLen int
		expectContains map[string]bool // map key -> bool (true if expected)
	}{
		{
			name:           "Successful fetch",
			mockKV:         &mockConsulKV{ipData: []byte(" 1.1.1.1 , 2.2.2.2,3.3.3.3 ")},
			expectedErr:    false,
			expectedMapLen: 3,
			expectContains: map[string]bool{"1.1.1.1": true, "2.2.2.2": true, "3.3.3.3": true, "4.4.4.4": false},
		},
		{
			name:           "Empty value",
			mockKV:         &mockConsulKV{ipData: []byte("")},
			expectedErr:    false,
			expectedMapLen: 0,
			expectContains: map[string]bool{"1.1.1.1": false},
		},
		{
			name:           "Key not found",
			mockKV:         &mockConsulKV{ipData: nil}, // nil simulates key not found
			expectedErr:    false,
			expectedMapLen: 0,
			expectContains: map[string]bool{"1.1.1.1": false},
		},
		{
			name:           "Consul error",
			mockKV:         &mockConsulKV{ipError: fmt.Errorf("consul connection error")},
			expectedErr:    true,
			expectedMapLen: 0, // Map should remain empty on error
		},
		{
			name:           "Malformed value (extra commas)",
			mockKV:         &mockConsulKV{ipData: []byte(",1.1.1.1,,2.2.2.2,")},
			expectedErr:    false,
			expectedMapLen: 2,
			expectContains: map[string]bool{"1.1.1.1": true, "2.2.2.2": true},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app := NewService(logger, tc.mockKV)
			err := app.FetchAndUpdateIPBlocklist()

			if (err != nil) != tc.expectedErr {
				t.Fatalf("FetchAndUpdateIPBlocklist() error = %v, expectedErr %v", err, tc.expectedErr)
			}

			// Lock is needed to safely read the map after potential modification
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

// --- Test FetchAndUpdateUABlocklist --- (New Test Function)

func TestFetchAndUpdateUABlocklist(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	testCases := []struct {
		name           string
		mockKV         *mockConsulKV
		expectedErr    bool
		expectedMapLen int
		expectContains map[string]bool // map key -> bool (true if expected)
	}{
		{
			name:           "Successful fetch",
			mockKV:         &mockConsulKV{uaData: []byte(" BadBot/1.0 , NastyCrawler/2.1, ExactUA String ")},
			expectedErr:    false,
			expectedMapLen: 3,
			expectContains: map[string]bool{"BadBot/1.0": true, "NastyCrawler/2.1": true, "ExactUA String": true, "GoodBot": false},
		},
		{
			name:           "Empty value",
			mockKV:         &mockConsulKV{uaData: []byte("")},
			expectedErr:    false,
			expectedMapLen: 0,
			expectContains: map[string]bool{"BadBot/1.0": false},
		},
		{
			name:           "Key not found",
			mockKV:         &mockConsulKV{uaData: nil}, // nil simulates key not found
			expectedErr:    false,
			expectedMapLen: 0,
			expectContains: map[string]bool{"BadBot/1.0": false},
		},
		{
			name:           "Consul error",
			mockKV:         &mockConsulKV{uaError: fmt.Errorf("consul connection error")},
			expectedErr:    true,
			expectedMapLen: 0, // Map should remain empty on error
		},
		{
			name:           "Malformed value (extra commas)",
			mockKV:         &mockConsulKV{uaData: []byte(",BadBot/1.0,,NastyCrawler/2.1,")},
			expectedErr:    false,
			expectedMapLen: 2,
			expectContains: map[string]bool{"BadBot/1.0": true, "NastyCrawler/2.1": true},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app := NewService(logger, tc.mockKV)
			err := app.FetchAndUpdateUABlocklist() // Test the new function

			if (err != nil) != tc.expectedErr {
				t.Fatalf("FetchAndUpdateUABlocklist() error = %v, expectedErr %v", err, tc.expectedErr)
			}

			// Lock is needed to safely read the map after potential modification
			app.configMutex.RLock()
			defer app.configMutex.RUnlock()

			if len(app.userAgentBlocklist) != tc.expectedMapLen { // Check the correct map
				t.Errorf("Expected map length %d, got %d", tc.expectedMapLen, len(app.userAgentBlocklist))
			}

			for key, expected := range tc.expectContains {
				_, actual := app.userAgentBlocklist[key] // Check the correct map
				if actual != expected {
					t.Errorf("For key %q, expected presence %v, got %v", key, expected, actual)
				}
			}
		})
	}
}
