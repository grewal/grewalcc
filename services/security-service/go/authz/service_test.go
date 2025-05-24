// File: services/security-service/go/authz/service_test.go
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
)

const (
	localTestIpBlocklistKVKey             = "config/security/ip_blocklist"
	localTestUaBlocklistKVKey             = "config/security/ua_blocklist"
	localTestL7RateLimitEnabledKey        = "config/security/ratelimit/enabled"
	localTestL7RateLimitLimitPerWindowKey = "config/security/ratelimit/limit_per_window"
	localTestL7RateLimitWindowSecondsKey  = "config/security/ratelimit/window_seconds"
	// Add other KV keys if your mock or tests for other FetchAndUpdate... methods need them
	// For example, if FetchAllConfigsFromConsul is tested implicitly through NewService
	localTestL4ConnRateLimitEnabledKey         = "config/security/l4_conn_ratelimit/enabled"
	localTestL4ConnRateLimitLimitPerWindowKey  = "config/security/l4_conn_ratelimit/limit_per_window"
	localTestL4ConnRateLimitWindowSecondsKey   = "config/security/l4_conn_ratelimit/window_seconds"
	localTestL4XDPBlocklistLogicEnabledKey     = "config/security/l4_xdp_blocklist_logic/enabled"
	localTestXDPGlobalEnabledKey               = "config/security/xdp/enabled"
)

type mockConsulKV struct {
	data                map[string][]byte
	specificErrorForKey map[string]error
}

func newMockConsulKV() *mockConsulKV { // Assuming newMockConsulKV is fine as unexported for test file
	return &mockConsulKV{
		data:                make(map[string][]byte),
		specificErrorForKey: make(map[string]error),
	}
}

func (m *mockConsulKV) SetData(key string, value []byte) {
	m.data[key] = value
}

func (m *mockConsulKV) SetError(key string, err error) {
	m.specificErrorForKey[key] = err
}

func (m *mockConsulKV) Get(key string, q *consulapi.QueryOptions) (*consulapi.KVPair, *consulapi.QueryMeta, error) {
	if err, exists := m.specificErrorForKey[key]; exists {
		return nil, nil, err
	}
	if data, exists := m.data[key]; exists {
		if data == nil { // Explicitly nil data means key not found behavior
			return nil, nil, nil
		}
		return &consulapi.KVPair{Key: key, Value: data}, nil, nil
	}
	return nil, nil, nil // Key not mocked, simulate key not found
}

func TestHandleAuthzRequest(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	testCases := []struct {
		name               string
		setupMockKV        func(m *mockConsulKV) // Function to set up mock KV for this test
		reqMethod          string
		reqPath            string
		reqHeaders         map[string]string
		expectedStatus     int
		expectedHeader     string
		expectedBodyFrag   string
		directRLOverride   bool // Flag to indicate if we directly override RL settings on app
		overrideRLEnabled  bool
		overrideRLLimit    int64
		overrideRLWindow   time.Duration
	}{
		{
			name: "Allowed IP, Allowed UA, RL Disabled by direct override",
			setupMockKV: func(m *mockConsulKV) {
				m.SetData(localTestIpBlocklistKVKey, []byte("1.1.1.1"))
				m.SetData(localTestUaBlocklistKVKey, []byte("BadBot/1.0"))
				// For this test, ensure RateLimit KV keys return values that would result in RL disabled, or rely on override
				m.SetData(localTestL7RateLimitEnabledKey, []byte("false"))
			},
			directRLOverride:  true, overrideRLEnabled: false, overrideRLLimit: 1, overrideRLWindow: 5 * time.Second,
			reqMethod:         http.MethodGet, reqPath: "/",
			reqHeaders:        map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "GoodAgent/2.0"},
			expectedStatus:    http.StatusOK, expectedHeader: "Allow", expectedBodyFrag: "OK",
		},
		{
			name: "Blocked IP",
			setupMockKV: func(m *mockConsulKV) {
				m.SetData(localTestIpBlocklistKVKey, []byte("1.1.1.1, 8.8.8.8"))
				m.SetData(localTestUaBlocklistKVKey, []byte("BadBot/1.0"))
				m.SetData(localTestL7RateLimitEnabledKey, []byte("false")) // Ensure RL off for this test
			},
			directRLOverride:  true, overrideRLEnabled: false,
			reqMethod:         http.MethodGet, reqPath: "/",
			reqHeaders:        map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "GoodAgent/2.0"},
			expectedStatus:    http.StatusForbidden, expectedHeader: "Deny-IPBlock", expectedBodyFrag: "Access Denied: IP blocked.",
		},
		{
			name: "Blocked UA",
			setupMockKV: func(m *mockConsulKV) {
				m.SetData(localTestIpBlocklistKVKey, []byte("1.1.1.1"))
				m.SetData(localTestUaBlocklistKVKey, []byte("BadBot/1.0\nAnotherBadBot"))
				m.SetData(localTestL7RateLimitEnabledKey, []byte("false")) // Ensure RL off for this test
			},
			directRLOverride:  true, overrideRLEnabled: false,
			reqMethod:         http.MethodGet, reqPath: "/",
			reqHeaders:        map[string]string{"X-Forwarded-For": "8.8.8.8", "User-Agent": "BadBot/1.0"},
			expectedStatus:    http.StatusForbidden, expectedHeader: "Deny-UABlock", expectedBodyFrag: "Access Denied: Client blocked.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockKV := newMockConsulKV()
			if tc.setupMockKV != nil {
				tc.setupMockKV(mockKV)
			}

			// Assumes NewService IS EXPORTED in service.go
			// and that it calls FetchAllConfigsFromConsul internally or through main.go's logic
			// This means app will be initialized with data from mockKV
			app := NewService(logger, mockKV, nil)

			// If NewService doesn't call FetchAll itself, then main.go would.
			// For the test, we ensure the app state reflects the mockKV.
			// Your actual FetchAllConfigsFromConsul is an exported func.
			ipList, uaList, l7RLCfg, l4ConnRLCfg, l4XDPLgcEnabled, xdpGlobEnabled, _ :=
				FetchAllConfigsFromConsul(mockKV, logger) // Call the exported FetchAll
			app.UpdateIPBlocklist(ipList)
			app.UpdateUABlocklist(uaList)
			app.UpdateL7RateLimitConfig(l7RLCfg)
			app.UpdateL4ConnRateLimitConfig(l4ConnRLCfg)
			app.UpdateL4XDPBlocklistLogicEnabled(l4XDPLgcEnabled)
			app.UpdateXDPGlobalEnabled(xdpGlobEnabled)


			if tc.directRLOverride { // Apply test-specific overrides AFTER initial load
				app.configMutex.Lock()
				app.l7RateLimitEnabled = tc.overrideRLEnabled
				app.l7RateLimitCount = tc.overrideRLLimit
				app.l7RateLimitWindow = tc.overrideRLWindow
				app.configMutex.Unlock()
			}


			req := httptest.NewRequest(tc.reqMethod, tc.reqPath, nil)
			for key, val := range tc.reqHeaders {
				req.Header.Set(key, val)
			}
			req = req.WithContext(context.Background())
			rr := httptest.NewRecorder()

			// Assuming NewHTTPAuthzServer and HandleAuthzRequest ARE EXPORTED
			httpAuthzHandler := NewHTTPAuthzServer(logger, app)
			handler := http.HandlerFunc(httpAuthzHandler.HandleAuthzRequest)
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
			if tc.expectedStatus == http.StatusTooManyRequests {
				if retryAfter := rr.Header().Get("Retry-After"); retryAfter == "" {
					t.Errorf("handler did not return Retry-After header on 429 status")
				}
			}
		})
	}
}

// Renamed to better reflect what it tests, assuming FetchAllConfigsFromConsul is the main entry point.
func TestService_IPBlocklist_PopulationViaFetchAll(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	testCases := []struct {
		name           string
		setupMockKV    func(m *mockConsulKV)
		expectedErr    bool 
		expectedMapLen int
		expectContains map[string]bool
	}{
		{
			name: "Successful IP fetch via FetchAll",
			setupMockKV: func(m *mockConsulKV) {
				m.SetData(localTestIpBlocklistKVKey, []byte(" 1.1.1.1 , 2.2.2.2,3.3.3.3 "))
			},
			expectedErr:    false,
			expectedMapLen: 3,
			expectContains: map[string]bool{"1.1.1.1": true, "2.2.2.2": true, "3.3.3.3": true, "4.4.4.4": false},
		},
		{
			name: "Consul error on IP key via FetchAll",
			setupMockKV: func(m *mockConsulKV) {
				m.SetError(localTestIpBlocklistKVKey, fmt.Errorf("consul connection error for IP key"))
			},
			expectedErr:    true, 
			expectedMapLen: 0,    
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockKV := newMockConsulKV()
			if tc.setupMockKV != nil {
				tc.setupMockKV(mockKV)
			}
			
			app := NewService(logger, mockKV, nil) // Assumes NewService IS EXPORTED
			
			// Simulate how main.go / poller would use FetchAllConfigsFromConsul and then update the service
			ipList, _, _, _, _, _, err := FetchAllConfigsFromConsul(mockKV, logger)
			app.UpdateIPBlocklist(ipList) // Assuming UpdateIPBlocklist is an exported method


			if (err != nil) != tc.expectedErr {
				t.Fatalf("FetchAllConfigsFromConsul() [for IP list part] error = %v, expectedErr %v", err, tc.expectedErr)
			}

			app.configMutex.RLock()
			defer app.configMutex.RUnlock()
			if len(app.ipBlocklist) != tc.expectedMapLen {
				t.Errorf("Expected map length %d, got %d. Map: %v", tc.expectedMapLen, len(app.ipBlocklist), app.ipBlocklist)
			}
			for key, expected := range tc.expectContains {
				if _, actual := app.ipBlocklist[key]; actual != expected {
					t.Errorf("For key %q, expected presence %v, got %v", key, expected, actual)
				}
			}
		})
	}
}

// Renamed to better reflect what it tests
func TestService_UABlocklist_PopulationViaFetchAll(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	testCases := []struct {
		name           string
		setupMockKV    func(m *mockConsulKV)
		expectedErr    bool
		expectedMapLen int
		expectContains map[string]bool
	}{
		{
			name: "Successful UA fetch with newlines via FetchAll",
			setupMockKV: func(m *mockConsulKV) {
				m.SetData(localTestUaBlocklistKVKey, []byte(" BadBot/1.0 \n NastyCrawler/2.1 \n ExactUA String \n"))
			},
			expectedErr:    false,
			expectedMapLen: 3,
			expectContains: map[string]bool{"BadBot/1.0": true, "NastyCrawler/2.1": true, "ExactUA String": true, "GoodBot": false},
		},
		{
			name: "Consul error on UA key via FetchAll",
			setupMockKV: func(m *mockConsulKV) {
				m.SetError(localTestUaBlocklistKVKey, fmt.Errorf("consul connection error for UA key"))
			},
			expectedErr:    true,
			expectedMapLen: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockKV := newMockConsulKV()
			if tc.setupMockKV != nil {
				tc.setupMockKV(mockKV)
			}
			
			app := NewService(logger, mockKV, nil) // Assumes NewService IS EXPORTED

			// Simulate how main.go / poller would use FetchAllConfigsFromConsul and then update the service
			_, uaList, _, _, _, _, err := FetchAllConfigsFromConsul(mockKV, logger)
			app.UpdateUABlocklist(uaList) // Assuming UpdateUABlocklist is an exported method

			if (err != nil) != tc.expectedErr {
				t.Fatalf("FetchAllConfigsFromConsul() [for UA list part] error = %v, expectedErr %v", err, tc.expectedErr)
			}

			app.configMutex.RLock()
			defer app.configMutex.RUnlock()
			if len(app.userAgentBlocklist) != tc.expectedMapLen {
				t.Errorf("Expected map length %d, got %d (Map: %v)", tc.expectedMapLen, len(app.userAgentBlocklist), app.userAgentBlocklist)
			}
			for key, expected := range tc.expectContains {
				if _, actual := app.userAgentBlocklist[key]; actual != expected {
					t.Errorf("For key %q, expected presence %v, got %v", key, expected, actual)
				}
			}
		})
	}
}
