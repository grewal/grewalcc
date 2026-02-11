#!/bin/bash
#
# Grewalcc Kernel Deployer
#

set -euo pipefail

# --- Configuration ---
INSTANCE_NAME="gcc-gem-a"
ZONE="us-central1-f"
PROJECT="mysides"
REMOTE_USER="ygrewal"

# --- Argument Parsing ---
ARTIFACT_DIR="${1:-}"

# --- UI Helpers ---
log() { echo -e "\e[32m[DEPLOY]\e[0m $1"; }
error() { echo -e "\e[31m[ERROR]\e[0m $1"; exit 1; }

# --- 1. Validation ---
if [ -z "$ARTIFACT_DIR" ]; then error "Usage: $0 <path>"; fi
if [ ! -d "$ARTIFACT_DIR" ]; then error "Directory not found: $ARTIFACT_DIR"; fi

IMAGE_DEB=$(find "$ARTIFACT_DIR" -maxdepth 1 -name "linux-image*grewalcc*.deb" ! -name "*dbg*" | head -n 1)
HEADERS_DEB=$(find "$ARTIFACT_DIR" -maxdepth 1 -name "linux-headers*grewalcc*.deb" | head -n 1)

if [ -z "$IMAGE_DEB" ] || [ -z "$HEADERS_DEB" ]; then
    error "Could not find valid clean .deb packages."
fi

log "Payload:     $(basename "$IMAGE_DEB")"
log "Headers:     $(basename "$HEADERS_DEB")"

# --- 2. Secure Transfer ---
log "Initiating Upload..."
gcloud compute scp --tunnel-through-iap --project="$PROJECT" --zone="$ZONE" --quiet \
    "$IMAGE_DEB" "$HEADERS_DEB" \
    "$REMOTE_USER@$INSTANCE_NAME":/tmp/

log "Upload Complete."

# --- 3. Remote Installation (The Fix) ---
log "Executing Remote Install..."

# Fix: We install FIRST, then clean up.
REMOTE_CMD="
    set -e
    echo '--- [REMOTE] Installing Kernel ---'
    sudo dpkg -i /tmp/linux-image*grewalcc*.deb /tmp/linux-headers*grewalcc*.deb
    
    echo '--- [REMOTE] Installation Successful. Cleaning up... ---'
    rm -f /tmp/linux-*grewalcc*.deb
    
    echo '--- [REMOTE] Rebooting... ---'
    sudo reboot
"

set +e
gcloud compute ssh "$REMOTE_USER@$INSTANCE_NAME" \
    --project="$PROJECT" \
    --zone="$ZONE" \
    --tunnel-through-iap \
    --command="$REMOTE_CMD"
SSH_EXIT=$?
set -e

# Exit code 255 is expected because reboot kills the SSH connection
if [ $SSH_EXIT -eq 255 ] || [ $SSH_EXIT -eq 0 ]; then
    echo -e "\n\e[34m=========================================================="
    echo "           DEPLOYMENT SUCCESSFUL"
    echo "=========================================================="
    echo "VM is rebooting. Wait 60s, then verify:"
    echo "   gcloud compute ssh $REMOTE_USER@$INSTANCE_NAME --command='uname -r'"
    echo -e "==========================================================\e[0m"
else
    error "Remote command failed with exit code $SSH_EXIT"
fi
