// File: services/security-service/go/main.go
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv" // For parsing XDP_GLOBAL_ENABLED_FROM_ENV
	"sync"
	"syscall"
	"time"

	// Corrected full module path imports
	"grewal.cc/services/security-service/go/authz"
	"grewal.cc/services/security-service/go/ebpfctrl"
	pb "grewal.cc/services/security-service/go/pkg/genproto/envoy/service/auth/v3" // For gRPC server

	consulapi "github.com/hashicorp/consul/api"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

// Configuration struct - kept in main.go for simplicity for now
type Config struct {
	HTTPListenAddr             string
	GRPCListenAddr             string
	ConsulAddr                 string
	RedisAddr                  string
	RedisPassword              string
	XDPLinkInterfaceName       string
	XDPObjectPath              string
	XDPMapRootPath             string
	XDPIPBlocklistMapName      string
	XDPProgramName             string
	XDPGlobalEnabledFromEnv    bool // Master switch for XDP functionality, from ENV
	XDPInitialSyncEnabled      bool // Controls if initial sync to eBPF map happens (derived from XDPGlobalEnabledFromEnv)
	XDPPollingSyncEnabled      bool // Controls if poller syncs to eBPF map (derived from XDPGlobalEnabledFromEnv)
	KVPollerInterval           time.Duration
}

func LoadConfig(logger *slog.Logger) Config {
	// Helper to get env var or default string
	getEnv := func(key, fallback string) string {
		if value, exists := os.LookupEnv(key); exists {
			return value
		}
		logger.Debug("Environment variable not set, using default.", "variable", key, "default", fallback)
		return fallback
	}
	// Helper to get env var for bool or default
	getEnvBool := func(key string, fallback bool) bool {
		if valueStr, exists := os.LookupEnv(key); exists {
			parsedVal, err := strconv.ParseBool(valueStr)
			if err == nil {
				return parsedVal
			}
			logger.Warn("Failed to parse boolean env var, using default.", "variable", key, "value_string", valueStr, "error", err, "default", fallback)
		}
		logger.Debug("Boolean environment variable not set, using default.", "variable", key, "default", fallback)
		return fallback
	}

	cfg := Config{
		HTTPListenAddr:             getEnv("HTTP_LISTEN_ADDR", ":9001"),
		GRPCListenAddr:             getEnv("GRPC_LISTEN_ADDR", ":9002"),
		ConsulAddr:                 getEnv("CONSUL_HTTP_ADDR", "10.128.0.22:8500"), // Default to host IP for Consul agent
		RedisAddr:                  getEnv("REDIS_ADDR", "127.0.0.1:6379"), // Default if running Redis on host, or "redis-server:6379" if on Docker network
		RedisPassword:              os.Getenv("REDIS_PASSWORD"), // No fallback for password
		XDPLinkInterfaceName:       getEnv("XDP_INTERFACE_NAME", ebpfctrl.DefaultXDPLinkInterface),
		XDPObjectPath:              getEnv("XDP_OBJECT_PATH", ebpfctrl.DefaultXDPObjPath),
		XDPMapRootPath:             getEnv("XDP_MAP_ROOT_PATH", ebpfctrl.DefaultBPFMapRootPath),
		XDPIPBlocklistMapName:      getEnv("XDP_IP_BLOCKLIST_MAP_NAME", ebpfctrl.DefaultIPBlocklistMapName),
		XDPProgramName:             getEnv("XDP_PROGRAM_NAME", ebpfctrl.DefaultXDPProgramName),
		XDPGlobalEnabledFromEnv:    getEnvBool("XDP_GLOBAL_ENABLED", true), // XDP on by default if env not set
	}

	// Derive sync enable flags from the global XDP enable flag
	cfg.XDPInitialSyncEnabled = cfg.XDPGlobalEnabledFromEnv
	cfg.XDPPollingSyncEnabled = cfg.XDPGlobalEnabledFromEnv
	
	// Poller interval
    pollerIntervalSecStr := getEnv("CONSUL_KV_POLLER_INTERVAL_SECONDS", "300") // 5 minutes default
    pollerIntervalSec, err := strconv.ParseInt(pollerIntervalSecStr, 10, 64)
    if err != nil || pollerIntervalSec <= 0 {
        logger.Warn("Invalid CONSUL_KV_POLLER_INTERVAL_SECONDS, using default 300s.", "value", pollerIntervalSecStr, "error", err)
        pollerIntervalSec = 300
    }
    cfg.KVPollerInterval = time.Duration(pollerIntervalSec) * time.Second


	logger.Info("Configuration loaded",
		slog.String("http_listen_address", cfg.HTTPListenAddr),
		slog.String("grpc_listen_address", cfg.GRPCListenAddr),
		slog.String("consul_address", cfg.ConsulAddr),
		slog.String("redis_address", cfg.RedisAddr),
		slog.Bool("redis_password_set", cfg.RedisPassword != ""),
		slog.String("xdp_interface_name", cfg.XDPLinkInterfaceName),
		slog.String("xdp_object_path", cfg.XDPObjectPath),
		slog.String("xdp_map_root_path", cfg.XDPMapRootPath),
		slog.String("xdp_ip_blocklist_map_name", cfg.XDPIPBlocklistMapName),
		slog.String("xdp_program_name", cfg.XDPProgramName),
		slog.Bool("xdp_global_enabled_from_env", cfg.XDPGlobalEnabledFromEnv),
		slog.Bool("xdp_initial_sync_enabled", cfg.XDPInitialSyncEnabled),
        slog.Bool("xdp_polling_sync_enabled_via_global_flag", cfg.XDPPollingSyncEnabled),
		slog.Duration("consul_kv_poller_interval", cfg.KVPollerInterval),
	)
	return cfg
}

func handleHealthz(client *consulapi.Client, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		consulOK := false
		if client != nil {
			if _, err := client.Agent().NodeName(); err == nil {
				consulOK = true
			} else {
				logger.ErrorContext(r.Context(), "Consul agent health check failed in /healthz", "error", err)
			}
		} else {
			logger.WarnContext(r.Context(), "/healthz check performed before Consul client was initialized")
		}

		if consulOK {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "OK")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "Service Unavailable")
		}
	}
}


func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))
	slog.SetDefault(logger)
	logger.Info("Starting Grewal Security Service...")

	cfg := LoadConfig(logger)

	// --- Consul Client Setup ---
	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = cfg.ConsulAddr
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		logger.Error("Fatal error creating Consul client", "error", err, "address", cfg.ConsulAddr)
		os.Exit(1)
	}
	if nodeName, err := consulClient.Agent().NodeName(); err != nil {
		logger.Warn("Could not verify Consul agent connection on startup", "error", err, "address", cfg.ConsulAddr)
	} else {
		logger.Info("Successfully connected to Consul agent", "node_name", nodeName, "address", cfg.ConsulAddr)
	}

	// --- Redis Client Setup ---
	var rdb *redis.Client // Declare rdb here
	if cfg.RedisAddr != "REDIS_DISABLED_FOR_TESTING" {
		rdbOpts := &redis.Options{Addr: cfg.RedisAddr, Password: cfg.RedisPassword, DB: 0}
		rdb = redis.NewClient(rdbOpts)
		ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelPing() // Ensure cancel is called
		pingErr := rdb.Ping(ctxPing).Err()
		if pingErr != nil {
			logger.Error("Fatal error connecting to Redis", "address", cfg.RedisAddr, "error", pingErr)
			os.Exit(1)
		}
		logger.Info("Successfully connected to Redis", "address", cfg.RedisAddr)
	} else {
		logger.Warn("Redis client explicitly disabled for testing via REDIS_ADDR.")
	}


	// --- Authorization Service Core Logic ---
	authzService := authz.NewService(logger, consulClient.KV(), rdb) // Pass rdb (can be nil if disabled)

	// Initial fetch of all configurations for authzService (L7/L4 rules, XDP global flag etc.)
	// This will populate authzService.ipBlocklist, authzService.xdpGlobalEnabled, etc.
	initialIPs, _, _, _, _, initialXDPGlobalEnabled, fetchErr :=
		authz.FetchAllConfigsFromConsul(consulClient.KV(), logger)
	if fetchErr != nil {
		logger.Error("Failed to fetch initial configurations from Consul KV, using defaults where applicable.", "error", fetchErr)
		// authzService will use its defaults if fetches fail
	} else {
		logger.Info("Successfully fetched initial configurations from Consul KV for authz.Service.")
		authzService.UpdateIPBlocklist(initialIPs) // And others, done by FetchAll in your authz/service.go
		// ... ensure authzService's internal xdpGlobalEnabled is also updated by FetchAllConfigs ...
		// This is handled by s.UpdateXDPGlobalEnabled(xdpGlobalEnabledFlag) in your PollConsulKV,
		// so initial FetchAllConfigsFromConsul should effectively set it in authzService too if structured that way.
		// Let's ensure main.go explicitly updates authzService with the fetched xdpGlobalEnabled flag.
		authzService.UpdateXDPGlobalEnabled(initialXDPGlobalEnabled)
	}


	// --- XDP Controller Setup & Initial Sync ---
	var xdpController *ebpfctrl.XDPController // Declare here so it's in scope for poller and shutdown

	if cfg.XDPGlobalEnabledFromEnv { // Master switch from ENV for XDP functionality
		logger.Info("XDP Global Enabled via environment config. Proceeding with XDP setup.")
		xdpOpts := ebpfctrl.XDPControllerOptions{
			Logger:             logger,
			ObjPath:            cfg.XDPObjectPath,
			ProgramName:        cfg.XDPProgramName,
			LinkInterfaceName:  cfg.XDPLinkInterfaceName,
			BPFFSMapRootPath:   cfg.XDPMapRootPath,
			IPBlocklistMapName: cfg.XDPIPBlocklistMapName,
		}
		var xdpErr error
		xdpController, xdpErr = ebpfctrl.NewXDPController(xdpOpts)
		if xdpErr != nil {
			logger.Error("Failed to initialize XDP controller", "error", xdpErr)
			xdpController = nil // Ensure it's nil on error
			logger.Warn("Continuing without XDP kernel-level IP blocking due to controller init error.")
		} else {
			if err := xdpController.LoadAndAttachProgram(); err != nil {
				logger.Error("Failed to load and attach XDP program", "error", err)
				// Attempt to detach/cleanup if LoadAndAttachProgram partially succeeded or failed
				if detachErr := xdpController.Close(); detachErr != nil { // Assuming Close also handles detach
					logger.Error("Error closing XDP controller after load/attach failure", "error", detachErr)
				}
				xdpController = nil // Ensure it's nil on error
				logger.Warn("Continuing without XDP kernel-level IP blocking active due to load/attach error.")
			} else {
				logger.Info("XDP program successfully loaded and attached.", "interface", cfg.XDPLinkInterfaceName)

				// Initial eBPF Map Sync - only if XDP loaded AND global XDP (from Consul) is enabled
				// The authzService.IsXDPGlobalEnabled() now reflects the value fetched from Consul by FetchAllConfigsFromConsul
				if authzService.IsXDPGlobalEnabled() { // Check the Consul-driven flag
					if cfg.XDPInitialSyncEnabled { // And the env-var derived initial sync flag
						logger.Info("Performing initial sync of IP blocklist to eBPF map (XDP Global & Initial Sync Enabled).")
						currentIPBlocklistSnapshot := authzService.GetIPBlocklistSnapshot() // Get IPs loaded by authzService
						if err := xdpController.SyncIPBlocklistToMap(currentIPBlocklistSnapshot); err != nil {
							logger.Error("Initial sync of IP blocklist to eBPF map failed", "error", err)
							authz.EbpfMapSyncTotal.WithLabelValues("initial_failure").Inc()
						} else {
							logger.Info("Successfully performed initial sync of IP blocklist to eBPF map.")
							authz.EbpfMapSyncTotal.WithLabelValues("initial_success").Inc()
						}
					} else {
						logger.Info("XDP Initial Sync is disabled by environment config, skipping initial eBPF map population.")
						authz.EbpfMapSyncTotal.WithLabelValues("initial_skipped_env_disabled").Inc()
					}
				} else {
					logger.Info("XDP Global flag from Consul KV is false. Skipping initial eBPF map sync and clearing map if XDP controller is active.")
					if err := xdpController.SyncIPBlocklistToMap(make(map[string]struct{})); err != nil { // Clear map
						logger.Error("Failed to clear eBPF map during initial setup when XDP global (KV) is false", "error", err)
						authz.EbpfMapSyncTotal.WithLabelValues("initial_clear_failure").Inc()
					} else {
						authz.EbpfMapSyncTotal.WithLabelValues("initial_clear_success_kv_disabled").Inc()
					}
				}
			}
		}
	} else {
		logger.Info("XDP Global functionality is DISABLED via environment variable (XDP_GLOBAL_ENABLED=false). XDP controller will not be initialized.")
		authz.EbpfMapSyncTotal.WithLabelValues("skipped_env_disabled_global").Inc()
	}


	// --- Start Background Poller ---
	// The poller will use authzService.IsXDPGlobalEnabled() (from Consul) to decide on sync.
	var wg sync.WaitGroup
	appCtx, appCancel := context.WithCancel(context.Background()) // Application context
	pollerQuitSignal := make(chan struct{}) // Specific quit signal for poller
	wg.Add(1)
	go authz.PollConsulKV(appCtx, authzService, consulClient.KV(), cfg.KVPollerInterval, logger, xdpController, &wg, pollerQuitSignal)


	// --- HTTP Server (L7 ext_authz & /healthz, /metrics) ---
	httpMux := http.NewServeMux()
	httpAuthzHandler := authz.NewHTTPAuthzServer(logger, authzService) // Create HTTP Authz handler
	httpMux.HandleFunc("/authz/", httpAuthzHandler.HandleAuthzRequest) // Assuming Envoy is configured to send L7 checks to /authz/ path
	httpMux.HandleFunc("/healthz", handleHealthz(consulClient, logger))
	httpMux.Handle("/metrics", promhttp.Handler()) // Serve Prometheus metrics

	httpServer := &http.Server{
		Addr:         cfg.HTTPListenAddr,
		Handler:      httpMux,
		ReadTimeout:  10 * time.Second, // Increased from 5s
		WriteTimeout: 15 * time.Second, // Increased from 10s
		IdleTimeout:  120 * time.Second,
	}
	httpServerErrChan := make(chan error, 1)
	go func() {
		logger.Info("HTTP Authorization Server listening", "address", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpServerErrChan <- fmt.Errorf("HTTP server ListenAndServe error: %w", err)
		} else {
			httpServerErrChan <- nil // Signal clean shutdown or no error
		}
	}()

	// --- gRPC Server (L4 ext_authz) ---
	grpcListener, err := net.Listen("tcp", cfg.GRPCListenAddr)
	if err != nil {
		logger.Error("Failed to listen for gRPC", "address", cfg.GRPCListenAddr, "error", err)
		// Gracefully stop HTTP server if gRPC fails to listen
		_ = httpServer.Shutdown(context.Background())
		os.Exit(1)
	}
	//networkAuthzGRPCHandler := authz.NewNetworkAuthzServer(authzService,logger) // Create L4 Network Authz handler
	grpcServer := grpc.NewServer()
	//pb.RegisterNetworkAuthorizationServer(grpcServer, networkAuthzGRPCHandler) // Register L4 handler
	pb.RegisterAuthorizationServer(grpcServer, httpAuthzHandler) // Also register L7 gRPC handler

	grpcServerErrChan := make(chan error, 1)
	go func() {
		logger.Info("gRPC Authorization Server listening", "address", cfg.GRPCListenAddr)
		if err := grpcServer.Serve(grpcListener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			grpcServerErrChan <- fmt.Errorf("gRPC server Serve error: %w", err)
		} else {
			grpcServerErrChan <- nil // Signal clean shutdown or no error
		}
	}()


	// --- Graceful Shutdown Handling ---
	shutdownSignalChan := make(chan os.Signal, 1)
	signal.Notify(shutdownSignalChan, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("All servers running. Waiting for shutdown signal or server error...")

	// Wait for a server error or a shutdown signal
	select {
	case err := <-httpServerErrChan:
		if err != nil {
			logger.Error("HTTP Server failed or stopped unexpectedly, initiating shutdown...", "error", err)
		} else {
			logger.Info("HTTP Server stopped cleanly, initiating shutdown...")
		}
		// If HTTP server stops (error or not), gracefully stop gRPC server
		appCancel() // Signal poller to stop via context
		grpcServer.GracefulStop()


	case err := <-grpcServerErrChan:
		if err != nil {
			logger.Error("gRPC Server failed or stopped unexpectedly, initiating shutdown...", "error", err)
		} else {
			logger.Info("gRPC Server stopped cleanly, initiating shutdown...")
		}
		// If gRPC server stops, gracefully stop HTTP server
		appCancel() // Signal poller to stop via context
		shutdownCtxHttp, httpShutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer httpShutdownCancel()
		_ = httpServer.Shutdown(shutdownCtxHttp)


	case sig := <-shutdownSignalChan:
		logger.Info("Shutdown signal received, initiating graceful shutdown...", "signal", sig.String())
		appCancel() // Signal poller to stop via context
		// Stop gRPC server first, then HTTP
		grpcServer.GracefulStop()
		logger.Info("gRPC server initiated graceful stop.")

		shutdownCtxHttp, httpShutdownCancel := context.WithTimeout(context.Background(), 10*time.Second) // Give HTTP server time to drain
		defer httpShutdownCancel()
		if err := httpServer.Shutdown(shutdownCtxHttp); err != nil {
			logger.Error("Graceful HTTP server shutdown failed", "error", err)
		} else {
			logger.Info("HTTP server shutdown gracefully.")
		}
	}

	// Wait for poller to finish
	logger.Info("Waiting for background tasks (Consul KV Poller) to complete...")
	close(pollerQuitSignal) // Signal poller to stop directly (alternative to context cancellation for this specific goroutine)
	pollerWaitTimeout := 10 * time.Second // Reduced from 20s
	pollerDoneChan := make(chan struct{})
	go func() { wg.Wait(); close(pollerDoneChan) }()
	select {
	case <-pollerDoneChan:
		logger.Info("Consul KV Poller completed.")
	case <-time.After(pollerWaitTimeout):
		logger.Warn("Timeout waiting for Consul KV Poller to complete.")
	}


	// Close Redis client if it was initialized
	if rdb != nil {
		if err := rdb.Close(); err != nil {
			logger.Error("Error closing Redis client", "error", err)
		} else {
			logger.Debug("Redis client closed.")
		}
	}

	// Detach XDP program if controller was initialized and program attached
	if xdpController != nil {
		logger.Info("Detaching XDP program as part of final shutdown...")
		if err := xdpController.Close(); err != nil { // Close now handles detach and unpin
			logger.Error("Error closing XDP controller (detaching/unpinning XDP program) during shutdown", "error", err)
		} else {
			logger.Info("XDP controller closed (program detached/unpinned) successfully.")
		}
	}

	// Check for any lingering errors from server goroutines if they exited cleanly before signal
        select {
        case err, ok := <-httpServerErrChan:
                if ok && err != nil { // Check if channel is open AND error is not nil
                        logger.Warn("Lingering HTTP server error after shutdown sequence", "error", err)
                }
        default:
                // No lingering error on httpServerErrChan, or channel closed
        }

        select {
        case err, ok := <-grpcServerErrChan:
                if ok && err != nil { // Check if channel is open AND error is not nil
                        logger.Warn("Lingering gRPC server error after shutdown sequence", "error", err)
                }
        default:
                // No lingering error on grpcServerErrChan, or channel closed
        }

	logger.Info("Grewal Security Service finished.")
}
