// File: services/security-service/go/ebpfctrl/controller.go
package ebpfctrl

import (
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
	DefaultXDPObjPath         = "/app/ebpf/kernel/xdp_ip_blocker.o" // Path inside the Docker container
	DefaultXDPProgramName     = "xdp_ip_blocker_prog"               // Must match SEC("...") in C code
	DefaultXDPLinkInterface   = "ens4"                              // Default interface
	DefaultBPFMapRootPath     = "/sys/fs/bpf/grewalcc"              // Base BPF FS path for your project
	DefaultIPBlocklistMapName = "ip_blocklist_map"                // Must match map name in C code
)

// XDPController manages the lifecycle of an XDP eBPF program and its maps.
type XDPController struct {
	logger                *slog.Logger
	objPath               string
	programName           string
	linkInterfaceName     string
	bpfFsMapRootPath      string      // Base path in BPF FS
	ipBlocklistMapName    string      // Name of the map as defined in C
	actualMapPinPath      string      // Full path to the pinned map file
	collectionSpec        *ebpf.CollectionSpec
	collection            *ebpf.Collection
	xdpProgram            *ebpf.Program
	attachedLink          link.Link
	ipBlocklistMap        *ebpf.Map
	linkInterfaceResolved *net.Interface // Store resolved interface
}

// XDPControllerOptions provides configuration for the XDPController.
type XDPControllerOptions struct {
	Logger             *slog.Logger
	ObjPath            string
	ProgramName        string
	LinkInterfaceName  string
	BPFFSMapRootPath   string
	IPBlocklistMapName string
}

// Represents the value stored in the eBPF map.
// For the IP blocklist, we only care about existence, so a dummy value.
// Needs to match the __u8 value type in the C eBPF map definition.
type ebpfMapValue struct {
	IsBlocked uint8 // Using uint8 as it's a single byte, 1 for blocked.
}

// ipStringToNBOUint32 converts an IPv4 string to its uint32 Network Byte Order representation.
func ipStringToNBOUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address string: %s", ipStr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}
	// Convert to uint32 in Network Byte Order
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3]), nil
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
	if opts.LinkInterfaceName == "" { // Changed from LinkInterface
		return nil, fmt.Errorf("network link interface name is required for XDPController")
	}
	if opts.BPFFSMapRootPath == "" {
		opts.BPFFSMapRootPath = DefaultBPFMapRootPath
	}
	if opts.IPBlocklistMapName == "" {
		opts.IPBlocklistMapName = DefaultIPBlocklistMapName
	}

	// Resolve interface once
	iface, err := net.InterfaceByName(opts.LinkInterfaceName)
	if err != nil {
		opts.Logger.Error("Failed to get network interface for XDP", "interface", opts.LinkInterfaceName, "error", err)
		return nil, fmt.Errorf("getting network interface %s: %w", opts.LinkInterfaceName, err)
	}

	ctrl := &XDPController{
		logger:                opts.Logger.With("component", "xdp_controller", "interface", opts.LinkInterfaceName),
		objPath:               opts.ObjPath,
		programName:           opts.ProgramName,
		linkInterfaceName:     opts.LinkInterfaceName,
		linkInterfaceResolved: iface, // Store resolved interface
		bpfFsMapRootPath:      opts.BPFFSMapRootPath,
		ipBlocklistMapName:    opts.IPBlocklistMapName,
		actualMapPinPath:      filepath.Join(opts.BPFFSMapRootPath, opts.IPBlocklistMapName),
	}

	ctrl.logger.Info("XDP Controller initialized",
		"object_path", ctrl.objPath,
		"program_name", ctrl.programName,
		"map_pin_path_full", ctrl.actualMapPinPath, // Log the full pin path
	)
	return ctrl, nil
}

// EnsureMapPinPathDir creates the directory for pinning BPF maps if it doesn't exist.
func (xc *XDPController) EnsureMapPinPathDir() error {
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		xc.logger.Error("BPF filesystem not mounted at /sys/fs/bpf")
		return fmt.Errorf("BPF filesystem not mounted at /sys/fs/bpf")
	}
	// Ensure the specific subdirectory for this map exists
	mapDir := filepath.Dir(xc.actualMapPinPath)
	if err := os.MkdirAll(mapDir, 0755); err != nil {
		xc.logger.Error("Failed creating BPF map pin directory", "path", mapDir, "error", err)
		return fmt.Errorf("creating BPF map pin directory %s: %w", mapDir, err)
	}
	return nil
}

func (xc *XDPController) LoadAndAttachProgram() error {
	xc.logger.Info("Attempting to load and attach XDP program...")

	if err := xc.EnsureMapPinPathDir(); err != nil {
		return err // Error already logged by EnsureMapPinPathDir
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		xc.logger.Error("Failed to remove memlock rlimit", "error", err)
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	// Attempt to load an existing pinned map first.
	// If it exists and matches spec, we might reuse or decide to replace.
	// For simplicity and robustness on startup, we'll unpin if it exists.
	if _, err := os.Stat(xc.actualMapPinPath); err == nil {
		xc.logger.Info("Pre-existing pinned map file found, attempting to remove for clean load.", "path", xc.actualMapPinPath)
		if removeErr := os.Remove(xc.actualMapPinPath); removeErr != nil {
			// Log warning but attempt to proceed; LoadPinnedMap might fail cleanly or NewCollection may overwrite.
			xc.logger.Warn("Failed to remove pre-existing pinned map file, continuing load attempt.", "path", xc.actualMapPinPath, "error", removeErr)
		} else {
			xc.logger.Info("Successfully removed pre-existing pinned map file.", "path", xc.actualMapPinPath)
		}
	} else if !os.IsNotExist(err) {
		// Some other error trying to stat the pin path
		xc.logger.Error("Error checking for pre-existing pinned map file", "path", xc.actualMapPinPath, "error", err)
		return fmt.Errorf("checking pre-existing map pin path %s: %w", xc.actualMapPinPath, err)
	}


	var err error
	xc.collectionSpec, err = ebpf.LoadCollectionSpec(xc.objPath)
	if err != nil {
		xc.logger.Error("Failed to load eBPF collection spec", "path", xc.objPath, "error", err)
		return fmt.Errorf("loading collection spec from %s: %w", xc.objPath, err)
	}

	mapSpecToLoad, ok := xc.collectionSpec.Maps[xc.ipBlocklistMapName]
	if !ok {
		xc.logger.Error("Map specification not found in collection spec", "map_name", xc.ipBlocklistMapName)
		return fmt.Errorf("map %s not found in eBPF object specification", xc.ipBlocklistMapName)
	}
	// Ensure userspace controls pinning for this map
	mapSpecToLoad.Pinning = ebpf.PinNone


	// Instantiate the collection
	// No need for CollectionOptions.Maps.ReplaceExisting if we are managing the pin file manually
	xc.collection, err = ebpf.NewCollection(xc.collectionSpec)
	if err != nil {
		xc.logger.Error("Failed to create new eBPF collection", "error", err)
		return fmt.Errorf("creating new eBPF collection: %w", err)
	}

	// Get the map from the instantiated collection.
	loadedMap, ok := xc.collection.Maps[xc.ipBlocklistMapName]
	if !ok {
		xc.logger.Error("Map not found in loaded eBPF collection", "map_name", xc.ipBlocklistMapName)
		xc.collection.Close() // Best effort close
		return fmt.Errorf("map %s not found in loaded collection", xc.ipBlocklistMapName)
	}
	xc.ipBlocklistMap = loadedMap

	// Explicitly pin the map to the desired path
	if err := xc.ipBlocklistMap.Pin(xc.actualMapPinPath); err != nil {
		xc.logger.Error("Failed to pin eBPF map", "map_name", xc.ipBlocklistMapName, "path", xc.actualMapPinPath, "error", err)
		xc.collection.Close() // Best effort close
		return fmt.Errorf("pinning map %s to %s: %w", xc.ipBlocklistMapName, xc.actualMapPinPath, err)
	}
	xc.logger.Info("Successfully pinned eBPF map", "map_name", xc.ipBlocklistMapName, "path", xc.actualMapPinPath)


	// Get the program from the collection
	prog, ok := xc.collection.Programs[xc.programName]
	if !ok {
		// Fallback: Try finding by section name if map key (program name) differs from section name
		// This shouldn't be necessary if C SEC("...") name matches Go programName constant
		var foundBySection bool
		var progKeyFromELF string
		for elfKey, pSpec := range xc.collectionSpec.Programs {
			if pSpec.SectionName == xc.programName {
				progKeyFromELF = elfKey
				prog, ok = xc.collection.Programs[progKeyFromELF]
				foundBySection = true
				break
			}
		}
		if !foundBySection || !ok {
			xc.logger.Error("XDP program not found in eBPF collection", "program_name_expected", xc.programName)
			xc.collection.Close() // Best effort close
			// We already pinned the map, attempt to unpin it on this error path
			if unpinErr := xc.ipBlocklistMap.Unpin(); unpinErr != nil {
				xc.logger.Error("Failed to unpin map after program load failure", "path", xc.actualMapPinPath, "error", unpinErr)
			}
			return fmt.Errorf("program %s not found in eBPF object", xc.programName)
		}
		xc.logger.Info("XDP program found by section name mapping in ELF", "elf_key", progKeyFromELF, "section_name", xc.programName)
	}
	xc.xdpProgram = prog


	// Attach the XDP program
	// xc.linkInterfaceResolved was set in NewXDPController
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   xc.xdpProgram,
		Interface: xc.linkInterfaceResolved.Index,
		Flags:     link.XDPGenericMode, // Or link.XDPDriverMode if NIC supports it
	})
	if err != nil {
		xc.logger.Error("Failed to attach XDP program", "error", err)
		xc.collection.Close() // Best effort close
		// Attempt to unpin map on attach failure
		if unpinErr := xc.ipBlocklistMap.Unpin(); unpinErr != nil {
			xc.logger.Error("Failed to unpin map after XDP attach failure", "path", xc.actualMapPinPath, "error", unpinErr)
		}
		return fmt.Errorf("attaching XDP program: %w", err)
	}
	xc.attachedLink = l

	xc.logger.Info("Successfully attached XDP program")
	return nil
}

// DetachProgram detaches the XDP program and cleans up resources.
func (xc *XDPController) Close() error { // Renamed to Close for idiomatic Go
	xc.logger.Info("Closing XDP controller and detaching program...")
	var firstErr error

	// Detach the XDP program by closing the link
	if xc.attachedLink != nil {
		if err := xc.attachedLink.Close(); err != nil {
			xc.logger.Error("Failed to close XDP link (detach program)", "error", err)
			firstErr = fmt.Errorf("closing XDP link: %w", err)
		} else {
			xc.logger.Info("XDP link closed (program detached).")
		}
		xc.attachedLink = nil
	}

	// Unpin the map if it was pinned and exists
	if xc.ipBlocklistMap != nil { // Check if map object exists
		// Check if the map is actually pinned before trying to unpin by path
		// IsPinned might not be reliable if map object is there but pin file was removed externally
		// So, we attempt os.Remove first, then Unpin if map object is valid.
		if _, err := os.Stat(xc.actualMapPinPath); err == nil {
			xc.logger.Info("Attempting to remove pinned map file directly", "path", xc.actualMapPinPath)
			if err := os.Remove(xc.actualMapPinPath); err != nil {
				xc.logger.Error("Failed to remove pinned map file", "path", xc.actualMapPinPath, "error", err)
				// Log and continue, maybe Unpin() can still work if map object is valid
				if firstErr == nil {
					firstErr = fmt.Errorf("removing pinned map file %s: %w", xc.actualMapPinPath, err)
				}
			} else {
				xc.logger.Info("Successfully removed pinned map file.", "path", xc.actualMapPinPath)
			}
		} else if !os.IsNotExist(err) {
			xc.logger.Warn("Error stating pinned map file before unpin attempt", "path", xc.actualMapPinPath, "error", err)
		}


		// Now try to unpin via the map object if it's valid,
		// this cleans up kernel references even if file was gone.
		// IsPinned() checks if map.fd is valid and map was pinned from this handle.
		if xc.ipBlocklistMap.IsPinned() { // Check if the map *object* thinks it's pinned
			xc.logger.Info("Attempting to unpin map object", "map_name", xc.ipBlocklistMapName, "pin_path_expected", xc.actualMapPinPath)
			if err := xc.ipBlocklistMap.Unpin(); err != nil {
				// This can error if the file was already removed, or other issues.
				xc.logger.Error("Failed to unpin map object", "map_name", xc.ipBlocklistMapName, "error", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("unpinning map object %s: %w", xc.ipBlocklistMapName, err)
				}
			} else {
				xc.logger.Info("Successfully unpinned map object", "map_name", xc.ipBlocklistMapName)
			}
		}
	}


	// Close the collection (which also closes maps and programs within it)
	if xc.collection != nil {
		xc.collection.Close(); 
	} else {
		xc.logger.Debug("eBPF collection closed.")
		xc.collection = nil
	}

	// Nil out fields
	xc.xdpProgram = nil
	xc.ipBlocklistMap = nil


	if firstErr == nil {
		xc.logger.Info("XDP controller closed successfully.")
	}
	return firstErr
}

// SyncIPBlocklistToMap synchronizes the given list of IP strings (from Consul)
// to the eBPF ip_blocklist_map.
// IPs in currentIPsFromConsul will be added/updated.
// IPs in the eBPF map but not in currentIPsFromConsul will be removed.
func (xc *XDPController) SyncIPBlocklistToMap(currentIPsFromConsul map[string]struct{}) error {
	if xc.ipBlocklistMap == nil {
		xc.logger.Error("eBPF IP blocklist map is not initialized, cannot sync.")
		return fmt.Errorf("eBPF IP blocklist map not initialized")
	}

	xc.logger.Debug("Starting sync of IP blocklist to eBPF map", "consul_ip_count", len(currentIPsFromConsul))

	// 1. Get all IPs currently in the eBPF map
	ipsCurrentlyInBPFMap := make(map[uint32]struct{})
	var mapKeyNBO_u32 uint32
	var mapVal ebpfMapValue // Match the C struct { uint8 }

	iter := xc.ipBlocklistMap.Iterate()
	for iter.Next(&mapKeyNBO_u32, &mapVal) {
		ipsCurrentlyInBPFMap[mapKeyNBO_u32] = struct{}{}
	}
	if err := iter.Err(); err != nil {
		xc.logger.Error("Failed to iterate eBPF map for current IPs", "error", err)
		return fmt.Errorf("iterating eBPF map: %w", err)
	}
	xc.logger.Debug("Current IPs in eBPF map before sync", "count", len(ipsCurrentlyInBPFMap))


	// 2. Add/Update IPs from Consul to eBPF map
	var addedCount, processedCount int
	valToAdd := ebpfMapValue{IsBlocked: 1} // uint8(1)

	for ipStr := range currentIPsFromConsul {
		processedCount++
		ipNBO_u32, err := ipStringToNBOUint32(ipStr)
		if err != nil {
			xc.logger.Warn("Invalid IP string in Consul blocklist, skipping", "ip_string", ipStr, "error", err)
			continue
		}

		// Check if IP is already in the BPF map (from our snapshot)
		// If it is, we don't need to Put it again, just remove from our snapshot to track.
		if _, existsInBPFAlready := ipsCurrentlyInBPFMap[ipNBO_u32]; existsInBPFAlready {
			delete(ipsCurrentlyInBPFMap, ipNBO_u32) // This IP is desired and already in map
			continue
		}

		// If it's not in BPF map, add it
		if err := xc.ipBlocklistMap.Put(ipNBO_u32, valToAdd); err != nil {
			xc.logger.Error("Failed to add/update IP in eBPF map", "ip_string", ipStr, "ip_nbo_u32", fmt.Sprintf("0x%x", ipNBO_u32), "error", err)
			// Continue to try other IPs
		} else {
			addedCount++
			xc.logger.Debug("Successfully added/updated IP in eBPF map", "ip_string", ipStr, "ip_nbo_u32", fmt.Sprintf("0x%x", ipNBO_u32))
		}
	}

	// 3. Remove IPs from eBPF map that are no longer in Consul list
	// ipsCurrentlyInBPFMap now only contains IPs that were in BPF map but NOT in the latest Consul list
	var removedCount int
	for ipNBO_u32_toRemove := range ipsCurrentlyInBPFMap {
		if err := xc.ipBlocklistMap.Delete(ipNBO_u32_toRemove); err != nil {
			xc.logger.Error("Failed to delete stale IP from eBPF map", "ip_nbo_u32", fmt.Sprintf("0x%x", ipNBO_u32_toRemove), "error", err)
		} else {
			removedCount++
			xc.logger.Info("Successfully deleted stale IP from eBPF map", "ip_nbo_u32", fmt.Sprintf("0x%x", ipNBO_u32_toRemove))
		}
	}

	xc.logger.Info("eBPF map synchronization complete", "consul_list_size", len(currentIPsFromConsul), "processed_for_add_update", processedCount, "newly_added_to_bpf", addedCount, "removed_from_bpf", removedCount)
	return nil
}

func (xc *XDPController) SyncHardcodedIPTest() error {
	if xc.ipBlocklistMap == nil {
		return fmt.Errorf("eBPF map not initialized for hardcoded test")
	}
	// Example: Block "12.75.116.99" (NBO: 0x0c4b7463)
	hardcodedTestIPStringForGoController := "12.75.116.99"

	keyNBO_u32, err := ipStringToNBOUint32(hardcodedTestIPStringForGoController)
	if err != nil {
		xc.logger.Error("Failed to convert hardcoded IP to NBO uint32", "ip", hardcodedTestIPStringForGoController, "error", err)
		return err
	}

	val := ebpfMapValue{IsBlocked: 1} // uint8(1)
	if err := xc.ipBlocklistMap.Put(keyNBO_u32, val); err != nil {
		xc.logger.Error("Failed to put hardcoded IP into eBPF map", "ip", hardcodedTestIPStringForGoController, "key_nbo_u32", fmt.Sprintf("0x%x", keyNBO_u32), "error", err)
		return err
	}
	xc.logger.Info("Successfully put hardcoded IP into eBPF map", "ip", hardcodedTestIPStringForGoController, "key_nbo_u32", fmt.Sprintf("0x%x", keyNBO_u32))
	return nil
}

// GetMapFD can be used for debugging or external tools if needed
func (xc *XDPController) GetMapFD() int {
	if xc.ipBlocklistMap != nil {
		return xc.ipBlocklistMap.FD()
	}
	return -1
}
