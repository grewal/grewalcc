// FILE: services/security-service/go/ebpfctrl/controller.go

package ebpfctrl

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	DefaultXDPObjPath         = "/app/ebpf/kernel/xdp_ip_blocker.o"
	DefaultXDPProgramName     = "xdp_ip_blocker_prog"
	DefaultXDPLinkInterface   = "ens4"
	DefaultBPFMapRootPath     = "/sys/fs/bpf/grewalcc"
	DefaultIPBlocklistMapName = "ip_blocklist_map"
)

type XDPController struct {
	logger                *slog.Logger
	objPath               string
	linkInterfaceName     string
	actualMapPinPath      string
	xdpObjs               xdp_ip_blockerObjects // Use the specific generated type
	attachedLink          link.Link
	linkInterfaceResolved *net.Interface
	isInitialized         bool
}

func New(logger *slog.Logger, interfaceName string) (*XDPController, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("getting network interface %s: %w", interfaceName, err)
	}

	ctrl := &XDPController{
		logger:                logger.With("component", "xdp_controller", "interface", interfaceName),
		objPath:               DefaultXDPObjPath,
		linkInterfaceName:     interfaceName,
		linkInterfaceResolved: iface,
		actualMapPinPath:      filepath.Join(DefaultBPFMapRootPath, DefaultIPBlocklistMapName),
	}

	if err := ctrl.loadAndAttachProgram(); err != nil {
		_ = ctrl.Close()
		return nil, err
	}

	return ctrl, nil
}

// ensureCleanPinPath ensures the pin directory exists and removes any stale pin file.
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
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking pin file %s: %w", xc.actualMapPinPath, err)
	}

	return nil
}

// loadAndAttachProgram contains the core initialization logic.
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

	ipsCurrentlyInBPFMap := make(map[uint32]struct{})
	var mapKeyNBO_u32 uint32
	var mapVal uint8
	iter := xc.xdpObjs.IpBlocklistMap.Iterate()
	for iter.Next(&mapKeyNBO_u32, &mapVal) {
		ipsCurrentlyInBPFMap[mapKeyNBO_u32] = struct{}{}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterating eBPF map: %w", err)
	}

	valToAdd := uint8(1)
	for ipStr := range currentIPsFromConsul {
		ipNBO_u32, err := ipStringToNBOUint32(ipStr)
		if err != nil {
			continue
		}
		if _, exists := ipsCurrentlyInBPFMap[ipNBO_u32]; exists {
			delete(ipsCurrentlyInBPFMap, ipNBO_u32)
			continue
		}
		_ = xc.xdpObjs.IpBlocklistMap.Put(ipNBO_u32, valToAdd)
	}

	for ipNBO_u32_toRemove := range ipsCurrentlyInBPFMap {
		_ = xc.xdpObjs.IpBlocklistMap.Delete(ipNBO_u32_toRemove)
	}

	return nil
}

// ipStringToNBOUint32 converts an IPv4 string to its uint32 Network Byte Order representation.
func ipStringToNBOUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP: %s", ipStr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("not an IPv4: %s", ipStr)
	}
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3]), nil
}
