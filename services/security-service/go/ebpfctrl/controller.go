package ebpfctrl

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
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
	logger             *slog.Logger
	objPath            string
	programName        string
	linkInterface      string
	bpfFsMapRootPath   string
	ipBlocklistMapName string

	collection     *ebpf.Collection
	xdpProgram     *ebpf.Program
	attachedLink   link.Link
	ipBlocklistMap *ebpf.Map
}

type XDPControllerOptions struct {
	Logger             *slog.Logger
	ObjPath            string
	ProgramName        string
	LinkInterface      string
	BPFFSMapRootPath   string
	IPBlocklistMapName string
}

type MapValue struct {
	Found uint8
}

func NewXDPController(opts XDPControllerOptions) (*XDPController, error) {
	if opts.Logger == nil {
		return nil, fmt.Errorf("logger is required for XDPController")
	}
	if opts.ObjPath == "" {
		opts.ObjPath = DefaultXDPObjPath
	}
	if opts.ProgramName == "" {
		opts.ProgramName = DefaultXDPProgramName
	}
	if opts.LinkInterface == "" {
		return nil, fmt.Errorf("network link interface name is required for XDPController")
	}
	if opts.BPFFSMapRootPath == "" {
		opts.BPFFSMapRootPath = DefaultBPFMapRootPath
	}
	if opts.IPBlocklistMapName == "" {
		opts.IPBlocklistMapName = DefaultIPBlocklistMapName
	}

	ctrl := &XDPController{
		logger:             opts.Logger.With("component", "xdp_controller", "interface", opts.LinkInterface),
		objPath:            opts.ObjPath,
		programName:        opts.ProgramName,
		linkInterface:      opts.LinkInterface,
		bpfFsMapRootPath:   opts.BPFFSMapRootPath,
		ipBlocklistMapName: opts.IPBlocklistMapName,
	}

	ctrl.logger.Info("XDP Controller initialized",
		"object_path", ctrl.objPath,
		"program_name", ctrl.programName,
		"map_pin_path_root", ctrl.bpfFsMapRootPath,
		"ip_blocklist_map_name", ctrl.ipBlocklistMapName,
	)
	return ctrl, nil
}

func (xc *XDPController) LoadAndAttachProgram() error {
	xc.logger.Info("Attempting to load and attach XDP program...")

	// Ensure BPF map directory exists before loading
	if err := xc.EnsureMapPinPathDir(); err != nil {
		xc.logger.Error("Failed to ensure BPF map directory exists", "error", err)
		return fmt.Errorf("ensuring BPF map directory: %w", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		xc.logger.Error("Failed to remove memlock rlimit", "error", err)
		return fmt.Errorf("failed to remove memlock rlimit: %w", err)
	}

	// Load the eBPF collection spec from the object file
	spec, err := ebpf.LoadCollectionSpec(xc.objPath)
	if err != nil {
		xc.logger.Error("Failed to load eBPF collection spec", "path", xc.objPath, "error", err)
		return fmt.Errorf("loading collection spec from %s: %w", xc.objPath, err)
	}

	// Create exact pin path for the blocklist map
	mapPinPath := filepath.Join(xc.bpfFsMapRootPath, xc.ipBlocklistMapName)

	// Check if map is already pinned
	pinnedMap, err := ebpf.LoadPinnedMap(mapPinPath, nil)
	if err == nil {
		// Map already exists, close and unpin it to avoid conflicts
		xc.logger.Info("Map already exists, unpinning it first", "path", mapPinPath)
		if err := pinnedMap.Unpin(); err != nil {
			xc.logger.Error("Failed to unpin existing map", "path", mapPinPath, "error", err)
			pinnedMap.Close()
			return fmt.Errorf("unpinning existing map: %w", err)
		}
		pinnedMap.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		xc.logger.Error("Error checking for existing pinned map", "path", mapPinPath, "error_type", fmt.Sprintf("%T", err), "error_is_not_exist_check_result", os.IsNotExist(err), "error_string", err.Error())
		return fmt.Errorf("checking for existing pinned map: %w", err)
	}

	// Set map specifications before collection creation
	if mapSpec, exists := spec.Maps[xc.ipBlocklistMapName]; exists {
		mapSpec.Pinning = 0
	} else {
		xc.logger.Error("Map specification not found in collection spec", "map_name", xc.ipBlocklistMapName)
		return fmt.Errorf("map %s not found in eBPF object specification", xc.ipBlocklistMapName)
	}

	// Load the collection without pinning options
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		xc.logger.Error("Failed to create new eBPF collection", "error", err)
		return fmt.Errorf("creating new eBPF collection: %w", err)
	}
	xc.collection = coll

	// Get the program
	prog, ok := xc.collection.Programs[xc.programName]
	if !ok {
		var foundBySection bool
		var progKeyFromSection string
		for specKeyInCollection, pSpec := range spec.Programs {
			if pSpec.SectionName == xc.programName {
				progKeyFromSection = specKeyInCollection
				prog, ok = xc.collection.Programs[progKeyFromSection]
				foundBySection = true
				break
			}
		}
		if !foundBySection || !ok {
			xc.logger.Error("Failed to find XDP program in collection", "program_name", xc.programName)
			if xc.collection != nil {
				xc.collection.Close()
			}
			return fmt.Errorf("program %s not found in eBPF object", xc.programName)
		}
	}
	xc.xdpProgram = prog

	// Get the map and pin it manually
	m, ok := xc.collection.Maps[xc.ipBlocklistMapName]
	if !ok {
		xc.logger.Error("Failed to find IP blocklist map in collection", "map_name", xc.ipBlocklistMapName)
		if xc.collection != nil {
			xc.collection.Close()
		}
		return fmt.Errorf("map %s not found in eBPF object", xc.ipBlocklistMapName)
	}

	// Pin the map manually to the correct location
	if err := m.Pin(mapPinPath); err != nil {
		xc.logger.Error("Failed to pin map", "map_name", xc.ipBlocklistMapName, "path", mapPinPath, "error", err)
		if xc.collection != nil {
			xc.collection.Close()
		}
		return fmt.Errorf("pinning map %s to %s: %w", xc.ipBlocklistMapName, mapPinPath, err)
	}
	xc.logger.Info("Successfully pinned map", "map_name", xc.ipBlocklistMapName, "path", mapPinPath)
	xc.ipBlocklistMap = m

	// Attach the XDP program to the network interface
	iface, err := net.InterfaceByName(xc.linkInterface)
	if err != nil {
		xc.logger.Error("Failed to get network interface", "interface", xc.linkInterface, "error", err)
		if xc.collection != nil {
			xc.collection.Close()
		}
		return fmt.Errorf("getting network interface %s: %w", xc.linkInterface, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   xc.xdpProgram,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		xc.logger.Error("Failed to attach XDP program", "interface", xc.linkInterface, "error", err)
		if xc.collection != nil {
			xc.collection.Close()
		}
		return fmt.Errorf("attaching XDP program: %w", err)
	}
	xc.attachedLink = l

	xc.logger.Info("Successfully attached XDP program", "interface", xc.linkInterface)
	return nil
}

func (xc *XDPController) DetachProgram() error {
	xc.logger.Info("Detaching XDP program...")
	var firstErr error

	if xc.attachedLink != nil {
		if err := xc.attachedLink.Close(); err != nil {
			xc.logger.Error("Failed to close XDP link", "error", err)
			firstErr = fmt.Errorf("closing XDP link: %w", err)
		}
		xc.attachedLink = nil
	}

	// Unpin the map before closing the collection
	if xc.ipBlocklistMap != nil {
		mapPinPath := filepath.Join(xc.bpfFsMapRootPath, xc.ipBlocklistMapName)
		if err := xc.ipBlocklistMap.Unpin(); err != nil {
			xc.logger.Error("Failed to unpin map", "map_name", xc.ipBlocklistMapName, "path", mapPinPath, "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("unpinning map %s: %w", xc.ipBlocklistMapName, err)
			}
		} else {
			xc.logger.Info("Successfully unpinned map", "map_name", xc.ipBlocklistMapName, "path", mapPinPath)
		}
	}

	if xc.collection != nil {
		xc.collection.Close()
		xc.collection = nil
	}

	if firstErr == nil {
		xc.logger.Info("XDP program detached successfully")
	}
	return firstErr
}

func (xc *XDPController) EnsureMapPinPathDir() error {
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return fmt.Errorf("BPF filesystem not mounted at /sys/fs/bpf")
	}
	
	if err := os.MkdirAll(xc.bpfFsMapRootPath, 0755); err != nil {
		return fmt.Errorf("creating BPF map directory %s: %w", xc.bpfFsMapRootPath, err)
	}
	
	info, err := os.Stat(xc.bpfFsMapRootPath)
	if err != nil {
		return fmt.Errorf("checking directory %s: %w", xc.bpfFsMapRootPath, err)
	}
	
	mode := info.Mode()
	if mode.Perm()&0755 != 0755 {
		if err := os.Chmod(xc.bpfFsMapRootPath, 0755); err != nil {
			xc.logger.Warn("Could not set proper permissions on BPF map directory", 
				"path", xc.bpfFsMapRootPath, 
				"current_perm", mode.Perm(), 
				"error", err)
		}
	}
	
	return nil
}

func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address")
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("not an IPv4 address")
	}
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3]), nil
}

func (xc *XDPController) SyncIPBlocklistToMap(currentIPsFromConsul map[string]struct{}) error {
	if xc.ipBlocklistMap == nil {
		return fmt.Errorf("eBPF IP blocklist map not initialized")
	}

	ipsInBPFMap := make(map[uint32]struct{})
	var mapKey uint32
	var mapVal MapValue

	iter := xc.ipBlocklistMap.Iterate()
	for iter.Next(&mapKey, &mapVal) {
		ipsInBPFMap[mapKey] = struct{}{}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterating eBPF map: %w", err)
	}

	var dummyValue MapValue
	dummyValue.Found = 1

	for ipStr := range currentIPsFromConsul {
		ipNetworkOrder, err := ipToUint32(ipStr)
		if err != nil {
			xc.logger.Info("Invalid IP in blocklist", "ip", ipStr, "error", err)
			continue
		}

		if _, exists := ipsInBPFMap[ipNetworkOrder]; !exists {
			if err := xc.ipBlocklistMap.Put(ipNetworkOrder, dummyValue); err != nil {
				xc.logger.Error("Failed to add IP to map", "ip", ipStr, "error", err)
			} else {
				xc.logger.Info("Added IP to blocklist map", "ip", ipStr)
			}
		}
		delete(ipsInBPFMap, ipNetworkOrder)
	}

	for ipToRemove := range ipsInBPFMap {
		if err := xc.ipBlocklistMap.Delete(ipToRemove); err != nil {
			xc.logger.Error("Failed to remove IP from map", "ip", ipToRemove, "error", err)
		} else {
			xc.logger.Info("Removed IP from blocklist map", "ip", ipToRemove)
		}
	}

	return nil
}
