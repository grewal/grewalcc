#!/bin/bash
#
# Grewalcc Kernel Build Orchestrator
# Usage: ./build_kernel_deb_package.sh [stable|mainline] [-f]
#

set -euo pipefail

# --- Configuration ---
CACHE_DIR="$HOME/src/kernel_cache"
BUILDS_ROOT="$HOME/src/kernel_builds"
DNA_CONFIG="$HOME/src/gcc-kernel/kernel/configs/grewalcc_kernel_blueprint.config"
LLVM_VER="21"
THREADS=$(nproc)

# --- Defaults ---
TARGET_TYPE="stable"
FORCE_BUILD=false

# --- Argument Parsing ---
for arg in "$@"; do
    case $arg in
        -f|--force) FORCE_BUILD=true ;;
        mainline|latest) TARGET_TYPE="mainline" ;;
        stable) TARGET_TYPE="stable" ;;
    esac
done

# --- UI Helpers ---
log() { echo -e "\e[32m[FORGE]\e[0m $1"; }
warn() { echo -e "\e[33m[CHECK]\e[0m $1"; }
error() { echo -e "\e[31m[ERROR]\e[0m $1"; exit 1; }

# --- 1. JSON API Version Discovery ---
log "Querying Official Kernel.org JSON API..."

KERNEL_VER=$(curl -s https://www.kernel.org/releases.json | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    target = '$TARGET_TYPE'
    found = None
    
    for release in data['releases']:
        if release['moniker'] == target:
            found = release['version']
            break
            
    if target == 'mainline' and found is None:
        for release in data['releases']:
            if release['moniker'] == 'stable':
                found = release['version']
                break

    if found:
        print(found)
    else:
        sys.exit(1)
except Exception:
    sys.exit(1)
") || error "Failed to parse JSON from kernel.org. API may be unreachable."

log "Target Identification: $KERNEL_VER ($TARGET_TYPE)"

# --- 2. Idempotency Check ---
WORKSPACE="$BUILDS_ROOT/$KERNEL_VER"
mkdir -p "$WORKSPACE"

# Check for header deb as success marker
if ls "$WORKSPACE"/linux-headers-"$KERNEL_VER"*grewalcc*.deb 1> /dev/null 2>&1; then
    if [ "$FORCE_BUILD" = true ]; then
        warn "Artifacts exist, but -f (force) passed. Rebuilding..."
    else
        log "Success: Artifacts for $KERNEL_VER already exist."
        exit 0
    fi
fi

# --- 3. Toolchain & Shim Setup ---
if ! dpkg -s "clang-$LLVM_VER" >/dev/null 2>&1; then
    log "Installing Clang $LLVM_VER..."
    sudo apt update -qq && sudo apt install -y -qq clang-$LLVM_VER lld-$LLVM_VER llvm-$LLVM_VER-dev libelf-dev build-essential bc flex bison python3 >/dev/null
fi

SHIM_DIR="$WORKSPACE/shim-bin"
mkdir -p "$SHIM_DIR"
for tool in clang clang++ ld.lld llvm-ar llvm-nm llvm-objcopy llvm-objdump llvm-readelf llvm-strip; do
    if [[ "$tool" == "ld.lld" ]]; then target="ld.lld-$LLVM_VER"; else target="$tool-$LLVM_VER"; fi
    ln -sf "/usr/bin/$target" "$SHIM_DIR/$tool"
done
export PATH="$SHIM_DIR:$PATH"

# --- 4. SHA256 Integrity Verification ---
mkdir -p "$CACHE_DIR"
MAJOR=$(echo "$KERNEL_VER" | cut -d. -f1)
TARBALL="linux-$KERNEL_VER.tar.xz"
CACHED_TARBALL="$CACHE_DIR/$TARBALL"
CHECKSUM_FILE="$CACHE_DIR/sha256sums.asc"
URL_BASE="https://cdn.kernel.org/pub/linux/kernel/v$MAJOR.x"

ensure_valid_source() {
    log "Fetching checksum manifest..."
    wget -qO "$CHECKSUM_FILE" "$URL_BASE/sha256sums.asc" || error "Failed to download sha256sums.asc"

    EXPECTED_HASH=$(grep "$TARBALL" "$CHECKSUM_FILE" | awk '{print $1}')
    if [ -z "$EXPECTED_HASH" ]; then
        error "Version $KERNEL_VER not found in sha256sums.asc"
    fi

    if [ -f "$CACHED_TARBALL" ]; then
        log "Checking integrity of existing cache..."
        CURRENT_HASH=$(sha256sum "$CACHED_TARBALL" | awk '{print $1}')
        
        if [ "$CURRENT_HASH" == "$EXPECTED_HASH" ]; then
            log "Integrity Verified: SHA256 matches."
            return 0
        else
            warn "Integrity Failure! Local file is corrupt."
            warn "Deleting corrupt file..."
            rm -f "$CACHED_TARBALL"
        fi
    else
        log "Cache Miss: File not found."
    fi

    log "Downloading $TARBALL..."
    wget -c -q --show-progress "$URL_BASE/$TARBALL" -O "$CACHED_TARBALL"

    log "Verifying new download..."
    NEW_HASH=$(sha256sum "$CACHED_TARBALL" | awk '{print $1}')
    if [ "$NEW_HASH" != "$EXPECTED_HASH" ]; then
        error "Download corrupted! Hash mismatch after fresh download."
    fi
    log "Download Verified."
}

ensure_valid_source

# --- 5. Build Preparation ---
cd "$WORKSPACE"
if [ ! -f "Makefile" ] || [ "$FORCE_BUILD" = true ]; then
    log "Unpacking source..."
    tar -xf "$CACHED_TARBALL" --strip-components=1
fi

if [ -f "$DNA_CONFIG" ]; then
    cp "$DNA_CONFIG" .config
else
    warn "No DNA config found. Using default defconfig."
    make LLVM=1 defconfig >/dev/null
fi

scripts/config --enable CONFIG_DEBUG_INFO_BTF
scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS ""
make LLVM=1 olddefconfig >/dev/null

# --- 6. The Clean Build ---
START_TIME=$(date +%s)
log "Starting build with $THREADS threads (Detected)..."

# FIX: Set KDEB_PKGVERSION to just the kernel version.
# This results in 'linux-image-6.18.10-grewalcc_6.18.10_amd64.deb'
make -j"$THREADS" bindeb-pkg \
    LLVM=1 \
    KCFLAGS="-O3 -march=native" \
    KDEB_PKGVERSION="${KERNEL_VER}"

# --- 7. Analytics ---
END_TIME=$(date +%s)
TOTAL_SECONDS=$((END_TIME - START_TIME))
MINUTES=$(awk "BEGIN {printf \"%.2f\", $TOTAL_SECONDS / 60}")
HOURS_SAVED=$(awk "BEGIN {printf \"%.2f\", ($TOTAL_SECONDS * $THREADS * 0.85 - $TOTAL_SECONDS) / 3600}")

echo -e "\n\e[34m=========================================================="
echo "           GREWALCC AUTOMATION REPORT"
echo "=========================================================="
echo "Kernel:          $KERNEL_VER"
echo "Threads:         $THREADS (Dynamic)"
echo "Build Time:      $MINUTES min"
echo "Core Savings:    $HOURS_SAVED hours"
echo "Artifacts:       $WORKSPACE"
echo -e "==========================================================\e[0m"
