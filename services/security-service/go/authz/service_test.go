package authz

import (
	"fmt"      // For creating errors in the mock if needed
	"io"       // For io.Discard
	"log/slog" // For creating a test logger
	"net/http" // For HTTP status codes
	"net/http/httptest" // Core package for testing HTTP handlers
	"strings"  // For checking response body
	"testing"  // The Go testing framework package

	// Add import for the real consulapi package to use its types like KVPair
	consulapi "github.com/hashicorp/consul/api"
)

// --- Mock Consul KV Implementation ---

// mockConsulKV is a test double (mock) for the consulKV interface.
// It allows us to simulate Consul KV behavior during tests without needing a real agent.
type mockConsulKV struct {
	// getValue holds the KVPair to return when Get is called. Can be nil.
	getValue *consulapi.KVPair
	// getError holds an error to return when Get is called. Can be nil.
	getError error
}

// Get implements the consulKV interface for the mock object.
// It returns the pre-configured KVPair and error stored in the mock struct fields.
func (m *mockConsulKV) Get(key string, q *consulapi.QueryOptions) (*consulapi.KVPair, *consulapi.QueryMeta, error) {
	// Return the pre-configured values for the test.
	return m.getValue, nil, m.getError
}

// --- End Mock Consul KV Implementation ---

// --- Test Functions ---

// TestHandleAuthzRequest uses table-driven tests to cover multiple scenarios
// for the HandleAuthzRequest method.
func TestHandleAuthzRequest(t *testing.T) {
	// Define a struct to hold the inputs and expected outputs for each test case.
	testCases := []struct {
		testName          string
		initialBlocklist  map[string]struct{}
		requestXFFHeader  string
		expectStatusCode  int
		expectBodyContent string
		expectDecision    string
	}{
		{
			testName:          "IP is in blocklist",
			initialBlocklist:  map[string]struct{}{"192.0.2.1": {}},
			requestXFFHeader:  "192.0.2.1",
			expectStatusCode:  http.StatusForbidden,
			expectBodyContent: "Access denied.",
			expectDecision:    "Deny-IPBlock",
		},
		{
			testName:          "IP is NOT in blocklist",
			initialBlocklist:  map[string]struct{}{"192.0.2.1": {}},
			requestXFFHeader:  "198.51.100.5",
			expectStatusCode:  http.StatusOK,
			expectBodyContent: "",
			expectDecision:    "Allow",
		},
		{
			testName:          "X-Forwarded-For header is missing",
			initialBlocklist:  map[string]struct{}{"192.0.2.1": {}},
			requestXFFHeader:  "", // Intentionally empty string to signify missing header
			expectStatusCode:  http.StatusOK,
			expectBodyContent: "",
			expectDecision:    "Allow",
		},
		{
			testName:          "X-Forwarded-For header is present but empty",
			initialBlocklist:  map[string]struct{}{"192.0.2.1": {}},
			requestXFFHeader:  " ", // Explicit space to test trimming
			expectStatusCode:  http.StatusOK,
			expectBodyContent: "",
			expectDecision:    "Allow",
		},
	}

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, tc := range testCases {
		tc := tc // Capture range variable

		t.Run(tc.testName, func(t *testing.T) {
			// Arrange
			app := NewService(discardLogger, nil) // Pass nil mock KV, HandleAuthzRequest doesn't use it directly
			app.ipBlocklist = tc.initialBlocklist

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			// Only set the header if the test case specifies a non-empty value for it.
			// This correctly simulates a missing header vs. a present-but-empty one.
			if tc.requestXFFHeader != "" {
				req.Header.Set("X-Forwarded-For", tc.requestXFFHeader)
			}

			rr := httptest.NewRecorder()

			// Act
			app.HandleAuthzRequest(rr, req)

			// Assert
			if status := rr.Code; status != tc.expectStatusCode {
				t.Errorf("status code mismatch: got %v want %v", status, tc.expectStatusCode)
			}

			actualBody := strings.TrimSpace(rr.Body.String())
			if tc.expectBodyContent != "" && !strings.Contains(actualBody, tc.expectBodyContent) {
				t.Errorf("body content mismatch: got %q, does not contain %q", actualBody, tc.expectBodyContent)
			} else if tc.expectBodyContent == "" && actualBody != "" {
				t.Errorf("expected empty body, but got %q", actualBody)
			}

			if header := rr.Header().Get("X-Authz-Decision"); header != tc.expectDecision {
				t.Errorf("X-Authz-Decision header mismatch: got %q want %q", header, tc.expectDecision)
			}
		})
	}
}

// TestFetchAndUpdateIPBlocklist tests the logic for fetching data from KV
// and updating the internal blocklist map, using a mock KV client.
func TestFetchAndUpdateIPBlocklist(t *testing.T) {
	// Define test cases for different KV responses/errors.
	testCases := []struct {
		testName        string
		mockKVResponse  *consulapi.KVPair
		mockKVError     error
		expectError     bool
		expectBlocklist map[string]struct{}
	}{
		{
			testName: "Successful fetch with valid IPs",
			mockKVResponse: &consulapi.KVPair{
				Key:   ipBlocklistKey,
				Value: []byte(" 192.0.2.1, 198.51.100.5 , 203.0.113.8 "),
			},
			mockKVError: nil,
			expectError: false,
			expectBlocklist: map[string]struct{}{
				"192.0.2.1":    {},
				"198.51.100.5": {},
				"203.0.113.8":  {},
			},
		},
		{
			testName:        "Consul key not found",
			mockKVResponse:  nil,
			mockKVError:     nil,
			expectError:     false,
			expectBlocklist: map[string]struct{}{},
		},
		{
			testName: "Consul key exists but value is empty",
			mockKVResponse: &consulapi.KVPair{
				Key:   ipBlocklistKey,
				Value: []byte(""),
			},
			mockKVError:     nil,
			expectError:     false,
			expectBlocklist: map[string]struct{}{},
		},
		{
			testName: "Consul key exists but value is whitespace",
			mockKVResponse: &consulapi.KVPair{
				Key:   ipBlocklistKey,
				Value: []byte("   "),
			},
			mockKVError:     nil,
			expectError:     false,
			expectBlocklist: map[string]struct{}{},
		},
		{
			testName:        "Error fetching from Consul",
			mockKVResponse:  nil,
			mockKVError:     fmt.Errorf("simulated Consul connection error"),
			expectError:     true,
			expectBlocklist: map[string]struct{}{}, // Expect blocklist remains unchanged (empty in this case)
		},
	}

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, tc := range testCases {
		tc := tc // Capture range variable

		t.Run(tc.testName, func(t *testing.T) {
			// Arrange
			mockKV := &mockConsulKV{ // Create the mock KV for this test case
				getValue: tc.mockKVResponse,
				getError: tc.mockKVError,
			}
			app := NewService(discardLogger, mockKV) // Inject the mock KV

			// Act
			err := app.FetchAndUpdateIPBlocklist()

			// Assert
			if tc.expectError {
				if err == nil {
					t.Errorf("expected an error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("did not expect an error, but got: %v", err)
				}
			}

			// Check map state safely
			app.configMutex.RLock()
			if len(app.ipBlocklist) != len(tc.expectBlocklist) {
				t.Errorf("blocklist map length mismatch: got %d want %d. Got map: %v", len(app.ipBlocklist), len(tc.expectBlocklist), app.ipBlocklist)
			} else {
				for expectedIP := range tc.expectBlocklist {
					if _, exists := app.ipBlocklist[expectedIP]; !exists {
						t.Errorf("expected IP %q not found in blocklist map. Got map: %v", expectedIP, app.ipBlocklist)
					}
				}
				// Optional: Check that no unexpected IPs are present
				for actualIP := range app.ipBlocklist {
					if _, exists := tc.expectBlocklist[actualIP]; !exists {
						t.Errorf("unexpected IP %q found in blocklist map. Expected map: %v", actualIP, tc.expectBlocklist)
					}
				}
			}
			app.configMutex.RUnlock()
		})
	}
}
