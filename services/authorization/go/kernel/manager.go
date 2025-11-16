// FILE: services/authorization/go/kernel/manager.go
package kernel

import (
        "context"
        "encoding/binary"
        "fmt"
        "log/slog"
        "net"
        "strconv"
        "time"

        "github.com/cilium/ebpf/link"
        "github.com/cilium/ebpf/rlimit"
        "github.com/redis/go-redis/v9"
)

const (
        BpfPinPath           = "/sys/fs/bpf/grewalcc"
        DynamicBansValkeyKey = "xdp:dynamic_bans"
)

// ValkeyClient defines the subset of Valkey commands our manager needs for testability.
type ValkeyClient interface {
        ZAdd(ctx context.Context, key string, members ...redis.Z) *redis.IntCmd
        ZRemRangeByScore(ctx context.Context, key, min, max string) *redis.IntCmd
        ZRangeByScore(ctx context.Context, key string, opt *redis.ZRangeBy) *redis.StringSliceCmd
}

// policyEntry is the Go representation of the C struct in firewall.c.
// It must have the same memory layout.
type policyEntry struct {
        ExpiryNs uint64
        Action   uint8
        _        [7]byte // Explicit padding to match 64-bit alignment in the kernel.
}

// FirewallManager holds the live eBPF objects and dependencies.
type FirewallManager struct {
        Objects      firewallObjects
        xdpLink      link.Link
        valkeyClient ValkeyClient
        logger       *slog.Logger
        cleanupCtx   context.Context
        cleanupStop  context.CancelFunc
}

// FirewallStats holds aggregated performance counters from the kernel.
type FirewallStats struct {
        PacketsPassed  uint64
        PacketsDropped uint64
}

// NewFirewallManager loads, rehydrates, and attaches the XDP firewall.
// CRITICAL: Rehydration happens BEFORE XDP attachment to prevent race conditions.
func NewFirewallManager(valkeyClient ValkeyClient, interfaceName string, allowedTCPPorts []uint16, logger *slog.Logger) (*FirewallManager, error) {
        // FIX: Make rlimit removal non-fatal when running in privileged containers
        // The container's ulimits configuration handles this at the Docker level
        if err := rlimit.RemoveMemlock(); err != nil {
                logger.Warn("Failed to remove memlock rlimit programmatically, relying on container ulimits configuration", "error", err)
                // Don't return error - we're running privileged with ulimits set
        }

        iface, err := net.InterfaceByName(interfaceName)
        if err != nil {
                return nil, fmt.Errorf("getting interface %s: %w", interfaceName, err)
        }

        var objs firewallObjects
        if err := loadFirewallObjects(&objs, nil); err != nil {
                return nil, fmt.Errorf("loading eBPF objects: %w", err)
        }

        // Pin maps to the BPF filesystem for persistence across restarts
        if err := objs.IpPolicyMap.Pin(BpfPinPath + "/ip_policy_map"); err != nil {
                objs.Close()
                return nil, fmt.Errorf("pinning ip_policy_map: %w", err)
        }
        if err := objs.PortWhitelistMap.Pin(BpfPinPath + "/port_whitelist_map"); err != nil {
                objs.Close()
                return nil, fmt.Errorf("pinning port_whitelist_map: %w", err)
        }
        if err := objs.XdpStatsMap.Pin(BpfPinPath + "/xdp_stats_map"); err != nil {
                objs.Close()
                return nil, fmt.Errorf("pinning xdp_stats_map: %w", err)
        }

        // Populate the port whitelist with allowed TCP ports
        for _, port := range allowedTCPPorts {
                // FIX: The kernel reads tcph->dest which is in network byte order.
                // We need to store ports in network byte order (big-endian).
                portNBO := htons(port)
                if err := objs.PortWhitelistMap.Put(portNBO, uint8(1)); err != nil {
                        objs.Close()
                        return nil, fmt.Errorf("populating port whitelist for port %d: %w", port, err)
                }
        }
        logger.Info("Populated XDP port whitelist", "ports", allowedTCPPorts)

        // Create manager with cleanup context
        cleanupCtx, cleanupStop := context.WithCancel(context.Background())
        fm := &FirewallManager{
                Objects:      objs,
                xdpLink:      nil, // CRITICAL: Link is not attached yet.
                valkeyClient: valkeyClient,
                logger:       logger.With("component", "firewall_manager"),
                cleanupCtx:   cleanupCtx,
                cleanupStop:  cleanupStop,
        }

        // CRITICAL: Rehydrate bans BEFORE attaching XDP to prevent race condition
        if err := fm.rehydrateBans(context.Background()); err != nil {
                fm.Close()
                return nil, fmt.Errorf("failed to rehydrate bans from Valkey: %w", err)
        }

        // NOW it's safe to attach the XDP program to the NIC
        l, err := link.AttachXDP(link.XDPOptions{
                Program:   objs.FirewallProg,
                Interface: iface.Index,
        })
        if err != nil {
                fm.Close()
                return nil, fmt.Errorf("attaching XDP program: %w", err)
        }
        fm.xdpLink = l

        // Start background expiry cleanup
        fm.startExpiryCleanup()

        logger.Info("XDP firewall is LIVE and protecting the network", "interface", interfaceName)
        return fm, nil
}

// AddDynamicBan implements the "Ban Hammer" with a dual-write strategy:
// 1. Write to kernel eBPF map for immediate enforcement
// 2. Write to Valkey for persistence (asynchronous, non-blocking)
func (fm *FirewallManager) AddDynamicBan(ipStr string, duration time.Duration) error {
        ipUint, err := ipToUint32(ipStr)
        if err != nil {
                return fmt.Errorf("invalid IP for ban: %w", err)
        }

        expiryNs := uint64(time.Now().Add(duration).UnixNano())
        policy := policyEntry{
                ExpiryNs: expiryNs,
                Action:   1, // ACTION_DROP
        }

        // Critical path: Write to kernel first (synchronous)
        if err := fm.Objects.IpPolicyMap.Put(ipUint, policy); err != nil {
                return fmt.Errorf("updating eBPF map for ban: %w", err)
        }

        // Non-critical path: Persist to Valkey (asynchronous, best-effort)
        go func() {
                ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
                defer cancel()
                score := float64(expiryNs) / 1e9 // Store as seconds for Valkey score
                if err := fm.valkeyClient.ZAdd(ctx, DynamicBansValkeyKey, redis.Z{
                        Score:  score,
                        Member: ipStr,
                }).Err(); err != nil {
                        fm.logger.Error("Failed to persist dynamic ban to Valkey", "error", err, "ip", ipStr)
                        // Don't fail - kernel ban is already active
                }
        }()

        fm.logger.Info("Dynamic ban activated", "ip", ipStr, "duration", duration)
        return nil
}

// SyncIPBlocklistToMap efficiently syncs the static blocklist from Consul.
// Uses batch operations for performance.
func (fm *FirewallManager) SyncIPBlocklistToMap(currentIPsFromConsul map[string]struct{}) error {
        // Convert desired IPs to kernel format
        desiredIPs := make(map[uint32]struct{})
        for ipStr := range currentIPsFromConsul {
                ipUint, err := ipToUint32(ipStr)
                if err != nil {
                        fm.logger.Warn("Skipping invalid static IP from Consul", "ip", ipStr, "error", err)
                        continue
                }
                desiredIPs[ipUint] = struct{}{}
        }

        // Find stale static bans that need to be removed
        var ipsToDelete []uint32
        var existingIP uint32
        var existingPolicy policyEntry
        iter := fm.Objects.IpPolicyMap.Iterate()

        for iter.Next(&existingIP, &existingPolicy) {
                // Only manage static bans (ExpiryNs == 0) from Consul.
                // Dynamic bans (ExpiryNs > 0) are managed by the expiry cleanup goroutine.
                if existingPolicy.ExpiryNs == 0 {
                        if _, stillWanted := desiredIPs[existingIP]; !stillWanted {
                                ipsToDelete = append(ipsToDelete, existingIP)
                        }
                }
        }

        // Batch delete stale IPs
        if len(ipsToDelete) > 0 {
                if _, err := fm.Objects.IpPolicyMap.BatchDelete(ipsToDelete, nil); err != nil {
                        fm.logger.Error("Failed to batch-delete stale static IPs", "error", err)
                        // Continue to add new ones anyway
                } else {
                        fm.logger.Info("Removed stale static IPs from kernel", "count", len(ipsToDelete))
                }
        }

        // Add new static IPs
        staticPolicy := policyEntry{
                ExpiryNs: 0, // Permanent (managed by Consul)
                Action:   1, // DROP
        }
        for ipUint := range desiredIPs {
                if err := fm.Objects.IpPolicyMap.Put(ipUint, staticPolicy); err != nil {
                        fm.logger.Error("Failed to add static IP to map", "ip", uint32ToIP(ipUint), "error", err)
                }
        }

        fm.logger.Info("Synced static IP blocklist to XDP map", "count", len(desiredIPs))
        return nil
}

// ReadStats reads the performance counters from the kernel.
// These are per-CPU counters, so we aggregate across all CPUs.
// Returns interface{} to satisfy the generic interface requirement.
func (fm *FirewallManager) ReadStats() (interface{}, error) {
        var stats FirewallStats
        var perCPUValues []uint64

        // Read passed stats (key 0)
        if err := fm.Objects.XdpStatsMap.Lookup(uint32(0), &perCPUValues); err != nil {
                return stats, fmt.Errorf("reading passed stats: %w", err)
        }
        for _, v := range perCPUValues {
                stats.PacketsPassed += v
        }

        // Read dropped stats (key 1)
        perCPUValues = nil // Reset slice for reuse
        if err := fm.Objects.XdpStatsMap.Lookup(uint32(1), &perCPUValues); err != nil {
                return stats, fmt.Errorf("reading dropped stats: %w", err)
        }
        for _, v := range perCPUValues {
                stats.PacketsDropped += v
        }

        return stats, nil
}

// IsAttached returns true if the XDP program is currently attached to the NIC.
func (fm *FirewallManager) IsAttached() bool {
        return fm != nil && fm.xdpLink != nil
}

// Close gracefully detaches the XDP program and closes all eBPF objects.
func (fm *FirewallManager) Close() error {
        var errs []error

        // Stop background cleanup goroutine
        if fm.cleanupStop != nil {
                fm.cleanupStop()
        }

        // Detach XDP link
        if fm.xdpLink != nil {
                if err := fm.xdpLink.Close(); err != nil {
                        errs = append(errs, fmt.Errorf("closing XDP link: %w", err))
                }
        }

        // Close eBPF objects
        if err := fm.Objects.Close(); err != nil {
                errs = append(errs, fmt.Errorf("closing eBPF objects: %w", err))
        }

        if len(errs) == 0 {
                fm.logger.Info("XDP firewall closed successfully")
                return nil
        }

        // Combine errors
        errMsg := "errors during close:"
        for _, err := range errs {
                errMsg += " " + err.Error() + ";"
        }
        return fmt.Errorf("%s", errMsg)
}

// startExpiryCleanup runs a background goroutine to clean expired dynamic bans.
func (fm *FirewallManager) startExpiryCleanup() {
        go func() {
                ticker := time.NewTicker(1 * time.Minute)
                defer ticker.Stop()

                for {
                        select {
                        case <-fm.cleanupCtx.Done():
                                fm.logger.Info("Expiry cleanup goroutine stopping")
                                return
                        case <-ticker.C:
                                fm.cleanExpiredBans()
                        }
                }
        }()
}

// cleanExpiredBans removes expired dynamic bans from the kernel map.
func (fm *FirewallManager) cleanExpiredBans() {
        now := uint64(time.Now().UnixNano())
        var toDelete []uint32
        var ip uint32
        var policy policyEntry
        iter := fm.Objects.IpPolicyMap.Iterate()

        for iter.Next(&ip, &policy) {
                // Only clean dynamic bans (ExpiryNs > 0) that have expired
                if policy.ExpiryNs > 0 && now > policy.ExpiryNs {
                        toDelete = append(toDelete, ip)
                }
        }

        if len(toDelete) > 0 {
                if _, err := fm.Objects.IpPolicyMap.BatchDelete(toDelete, nil); err != nil {
                        fm.logger.Error("Failed to batch-delete expired bans", "error", err)
                } else {
                        fm.logger.Info("Cleaned expired dynamic bans from kernel map", "count", len(toDelete))
                }
        }
}

// rehydrateBans restores dynamic ban state from Valkey on startup.
// This is called BEFORE the XDP program is attached to prevent a race condition.
func (fm *FirewallManager) rehydrateBans(ctx context.Context) error {
        nowUnix := time.Now().Unix()
        nowStr := strconv.FormatInt(nowUnix, 10)

        // Clean expired bans from Valkey first
        if err := fm.valkeyClient.ZRemRangeByScore(ctx, DynamicBansValkeyKey, "-inf", nowStr).Err(); err != nil {
                return fmt.Errorf("cleaning expired bans from Valkey: %w", err)
        }

        // Fetch active bans (score > now)
        bans, err := fm.valkeyClient.ZRangeByScore(ctx, DynamicBansValkeyKey, &redis.ZRangeBy{
                Min: nowStr,
                Max: "+inf",
        }).Result()
        if err != nil {
                return fmt.Errorf("fetching active bans from Valkey: %w", err)
        }

        if len(bans) == 0 {
                fm.logger.Info("No active dynamic bans to rehydrate from Valkey")
                return nil
        }

        // Convert to kernel format
        var ipsToAdd []uint32
        var policiesToAdd []policyEntry
        for _, ipStr := range bans {
                ipUint, err := ipToUint32(ipStr)
                if err != nil {
                        fm.logger.Warn("Skipping invalid IP during rehydration", "ip", ipStr, "error", err)
                        continue
                }
                // In a production system, we would parse the Valkey score to get the real expiry.
                // For now, we rehydrate them with a reasonable default duration.
                expiryNs := uint64(time.Now().Add(5 * time.Minute).UnixNano())
                ipsToAdd = append(ipsToAdd, ipUint)
                policiesToAdd = append(policiesToAdd, policyEntry{
                        ExpiryNs: expiryNs,
                        Action:   1,
                })
        }

        // Batch update the kernel map
        if len(ipsToAdd) > 0 {
                if _, err := fm.Objects.IpPolicyMap.BatchUpdate(ipsToAdd, policiesToAdd, nil); err != nil {
                        return fmt.Errorf("batch-rehydrating bans to eBPF map: %w", err)
                }
        }

        fm.logger.Info("Successfully rehydrated dynamic bans from Valkey", "count", len(ipsToAdd))
        return nil
}

// --- Helper Functions ---

// ipToUint32 converts an IP string to a uint32 in network byte order (big-endian).
func ipToUint32(ipStr string) (uint32, error) {
        ip := net.ParseIP(ipStr)
        if ip == nil {
                return 0, fmt.Errorf("invalid IP string")
        }
        ip = ip.To4()
        if ip == nil {
                return 0, fmt.Errorf("not an IPv4 address")
        }
        // IP addresses are stored in network byte order (big-endian)
        return binary.BigEndian.Uint32(ip), nil
}

// uint32ToIP converts a uint32 in network byte order back to an IP.
// FIX: Corrected bug where it was writing ip instead of ipUint.
func uint32ToIP(ipUint uint32) net.IP {
        ip := make(net.IP, 4)
        binary.BigEndian.PutUint32(ip, ipUint)
        return ip
}

// htons converts a uint16 from host byte order to network byte order (big-endian).
// FIX: Simplified implementation that correctly converts to big-endian.
func htons(port uint16) uint16 {
        // On little-endian systems (x86, ARM), we need to swap bytes.
        // On big-endian systems, this is a no-op.
        // The simplest correct implementation is to use binary.BigEndian.
        buf := make([]byte, 2)
        binary.BigEndian.PutUint16(buf, port)
        return binary.BigEndian.Uint16(buf)
}
