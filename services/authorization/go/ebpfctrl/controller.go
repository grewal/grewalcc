// FILE: services/authorization/go/ebpfctrl/controller.go
package ebpfctrl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	//	"github.comcom/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -Wall -I/usr/include/bpf" -type ip_block_entry xdp_ip_blocker ../../ebpf/kernel/xdp_ip_blocker.c -- -I../../ebpf/headers

type XDPController struct {
	logger                *slog.Logger
	linkInterfaceName     string
	actualMapPinPath      string
	xdpObjs               xdp_ip_blockerObjects
	attachedLink          link.Link
	linkInterfaceResolved *net.Interface
	isInitialized         bool
}

func New(logger *slog.Logger, interfaceName string, mapRootPath string) (*XDPController, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("getting network interface %s: %w", interfaceName, err)
	}

	ctrl := &XDPController{
		logger:                logger.With("component", "xdp_controller", "interface", interfaceName),
		linkInterfaceName:     interfaceName,
		linkInterfaceResolved: iface,
		actualMapPinPath:      filepath.Join(mapRootPath, "ip_blocklist_map"),
	}

	if err := ctrl.loadAndAttachProgram(); err != nil {
		_ = ctrl.Close()
		return nil, err
	}

	return ctrl, nil
}

func (xc *XDPController) ensureCleanPinPath() error {
	pinDir := filepath.Dir(xc.actualMapPinPath)
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		return fmt.Errorf("creating pin directory %s: %w", pinDir, err)
	}

	if _, err := os.Stat(xc.actualMapPinPath); err == nil {
		xc.logger.Info("Found existing pin file, removing stale pin", "path", xc.actualMapPinPath)
		if err := os.Remove(xc.actualMapPinPath); err != nil {
			return fmt.Errorf("removing stale pin file %s: %w", xc.actualMapPinPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking pin file %s: %w", xc.actualMapPinPath, err)
	}

	return nil
}

func (xc *XDPController) loadAndAttachProgram() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}
	if err := xc.ensureCleanPinPath(); err != nil {
		return fmt.Errorf("preparing pin path: %w", err)
	}

	var objs xdp_ip_blockerObjects
	if err := loadXdp_ip_blockerObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	if err := objs.IpBlocklistMap.Pin(xc.actualMapPinPath); err != nil {
		_ = objs.Close()
		return fmt.Errorf("pinning map: %w", err)
	}

	prog := objs.XdpIpBlockerProg
	if prog == nil {
		_ = objs.IpBlocklistMap.Unpin()
		_ = objs.Close()
		return fmt.Errorf("program field XdpIpBlockerProg is nil in loaded eBPF objects")
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: xc.linkInterfaceResolved.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		_ = objs.IpBlocklistMap.Unpin()
		_ = objs.Close()
		return fmt.Errorf("attaching XDP program: %w", err)
	}

	xc.xdpObjs = objs
	xc.attachedLink = l
	xc.isInitialized = true

	xc.logger.Info("Successfully loaded, pinned, and attached XDP program.")
	return nil
}

func (xc *XDPController) IsInitialized() bool {
	if xc == nil {
		return false
	}
	return xc.isInitialized
}

func (xc *XDPController) Close() error {
	var firstErr error

	if xc.attachedLink != nil {
		if err := xc.attachedLink.Close(); err != nil {
			firstErr = fmt.Errorf("closing XDP link: %w", err)
		}
	}

	if err := xc.xdpObjs.Close(); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("closing eBPF objects: %w", err)
		}
	}

	xc.isInitialized = false
	return firstErr
}

func (xc *XDPController) SyncIPBlocklistToMap(currentIPsFromConsul map[string]struct{}) error {
	if !xc.IsInitialized() {
		return fmt.Errorf("cannot sync, XDP controller not initialized")
	}

	keysInBPFMap := make(map[uint32]struct{})
	var mapKeyNBO_u32 uint32
	var mapVal uint8
	iter := xc.xdpObjs.IpBlocklistMap.Iterate()
	for iter.Next(&mapKeyNBO_u32, &mapVal) {
		keysInBPFMap[mapKeyNBO_u32] = struct{}{}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterating eBPF map: %w", err)
	}

	valToAdd := uint8(1)
	for ipStr := range currentIPsFromConsul {
		ipNBO_u32, err := ipStringToNBOUint32(ipStr)
		if err != nil {
			xc.logger.Warn("Failed to parse IP from Consul, skipping", "ip", ipStr, "error", err)
			continue
		}

		if _, exists := keysInBPFMap[ipNBO_u32]; exists {
			delete(keysInBPFMap, ipNBO_u32)
		} else {
			if err := xc.xdpObjs.IpBlocklistMap.Put(ipNBO_u32, valToAdd); err != nil {
				xc.logger.Error("Failed to add IP to eBPF map", "ip", ipStr, "error", err)
			} else {
				xc.logger.Info("Added IP to blocklist map", "ip", ipStr)
			}
		}
	}

	for ipNBO_u32_toRemove := range keysInBPFMap {
		if err := xc.xdpObjs.IpBlocklistMap.Delete(ipNBO_u32_toRemove); err != nil {
			xc.logger.Error("Failed to delete stale IP from eBPF map", "ip_nbo_u32", ipNBO_u32_toRemove, "error", err)
		}
	}
	xc.logger.Info("Successfully synced IP blocklist to eBPF map", "consul_count", len(currentIPsFromConsul))
	return nil
}

func ipStringToNBOUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP string: %s", ipStr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}

	// To4() returns network byte order (big-endian) bytes.
	// On our little-endian host, we must interpret these bytes as little-endian
	// to produce a uint32 whose in-memory representation matches the network byte order
	// expected by the eBPF map. This compiles to a single, efficient BSWAP instruction.
	return binary.LittleEndian.Uint32(ipv4), nil
}
