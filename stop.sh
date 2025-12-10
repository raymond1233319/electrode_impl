#!/bin/bash

# Stop any existing processes locally and on all remote replicas listed in config.txt.
# Optional: pass --full to also detach TC filters/qdisc and remove pinned BPF maps/programs.

# Configuration (keep in sync with deploy.sh)
PASSWORD="5>EB:Qg4\$BS:fuV"
CONFIG_FILE="config.txt"
REMOTE_DIR="~/Electrode"
NETWORK_INTERFACE="eth1"
BPF_DIR="electrode"
BPF_EXECUTABLE="electrode"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Flags
FULL_CLEAN=1

# Helpers
ssh_exec() {
  local ip=$1
  local command=$2
  sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "root@$ip" "$command"
}

# Discover replicas
log_info "Parsing $CONFIG_FILE for replica IP addresses..."
REPLICA_IPS=()
INDEX=0
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ $line =~ ^replica[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):[0-9]+ ]]; then
    IP="${BASH_REMATCH[1]}"
    REPLICA_IPS+=("$IP")
    log_info "Found replica $INDEX: $IP"
    INDEX=$((INDEX + 1))
  fi
done < "$CONFIG_FILE"

if [ ${#REPLICA_IPS[@]} -eq 0 ]; then
  log_error "No replica IP addresses found in $CONFIG_FILE"
  exit 1
fi

# Determine local addresses for NETWORK_INTERFACE
LOCAL_INTERFACE_IPS=()
while read -r addr; do
  LOCAL_INTERFACE_IPS+=("$addr")
done < <(ip -4 addr show "$NETWORK_INTERFACE" | awk '/inet / {print $2}' | cut -d'/' -f1)

is_local_ip() {
  local target="$1"
  for candidate in "${LOCAL_INTERFACE_IPS[@]}"; do
    if [[ "$candidate" == "$target" ]]; then
      return 0
    fi
  done
  return 1
}

stop_local() {
  log_info "Stopping local processes (replica and XDP user program)"
  sudo pkill -f './bench/replica' || true
  sudo pkill -f "./$BPF_EXECUTABLE" || true

  log_info "Detaching XDP program from $NETWORK_INTERFACE locally"
  sudo ip link set dev "$NETWORK_INTERFACE" xdpoff 2>/dev/null || \
    sudo ip link set dev "$NETWORK_INTERFACE" xdp off 2>/dev/null || true

  if [[ $FULL_CLEAN -eq 1 ]]; then
    log_info "Detaching TC filters/qdisc and removing pinned BPF maps/programs locally"
    sudo tc filter del dev "$NETWORK_INTERFACE" egress 2>/dev/null || true
    sudo tc qdisc del dev "$NETWORK_INTERFACE" clsact 2>/dev/null || true
    sudo find /sys/fs/bpf -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
  fi
}

stop_remote() {
  local ip="$1"
  log_info "Stopping remote processes on $ip"
  ssh_exec "$ip" "pkill -f './bench/replica' || true"
  ssh_exec "$ip" "pkill -f "./$BPF_EXECUTABLE" || true"

  log_info "Detaching XDP program from $NETWORK_INTERFACE on $ip"
  ssh_exec "$ip" "ip link set dev $NETWORK_INTERFACE xdpoff 2>/dev/null || ip link set dev $NETWORK_INTERFACE xdp off 2>/dev/null || true"

  if [[ $FULL_CLEAN -eq 1 ]]; then
    log_info "Detaching TC filters/qdisc and removing pinned BPF maps/programs on $ip"
    ssh_exec "$ip" "tc filter del dev $NETWORK_INTERFACE egress 2>/dev/null || true"
    ssh_exec "$ip" "tc qdisc del dev $NETWORK_INTERFACE clsact 2>/dev/null || true"
    ssh_exec "$ip" "find /sys/fs/bpf -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true"
  fi
}

# Ensure sshpass is present
if ! command -v sshpass &> /dev/null; then
  log_error "sshpass is not installed. Installing..."
  sudo apt-get update && sudo apt-get install -y sshpass
fi

# Stop remote replicas first, then local
for idx in "${!REPLICA_IPS[@]}"; do
  IP="${REPLICA_IPS[$idx]}"
  if is_local_ip "$IP"; then
    continue
  fi
  # Verify connectivity but proceed even if it fails
  ssh_exec "$IP" "echo 'connected'" >/dev/null 2>&1 || log_warn "Could not verify SSH to $IP; attempting stop anyway"
  stop_remote "$IP"
  sleep 0.2
done

# Finally stop local
stop_local

log_info "Stop operation completed${FULL_CLEAN:+ (full cleanup)}."
