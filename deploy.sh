#!/bin/bash

# Configuration
PASSWORD=""
CONFIG_FILE="config.txt"
LOCAL_CONFIG_FILE="config.txt"
REMOTE_DIR="~/Electrode"
NETWORK_INTERFACE="eth1"

KNOWN_HOSTS_FILE="$HOME/.ssh/known_hosts"
BPF_DIR="electrode"
BPF_EXECUTABLE="electrode"
BPF_OBJECT="$BPF_DIR/electrode.ebpf.o"
BPF_SECTION="tc_broadcast"
MAC_CONFIG_FILE="electrode/mac_config.txt"
INTERFACE_CONFIG_FILE="$BPF_DIR/interface_config.txt"

# Source local env flags if present
if [[ -f ./.env.local ]]; then
    # shellcheck disable=SC1091
    source ./.env.local
fi

# Normalize flags to simple true/false strings
APPLY_TC_BROADCAST=${APPLY_TC_BROADCAST:-false}
APPLY_WAIT_ON_QUORUM=${APPLY_WAIT_ON_QUORUM:-false}
APPLY_FAST_REPLY=${APPLY_FAST_REPLY:-false}

# Compose macro flags for builds
EXTRA_CFLAGS=""
CXX_MACROS=""
if [[ "$APPLY_TC_BROADCAST" == "true" ]]; then
    EXTRA_CFLAGS+=" -DTC_BROADCAST"
    CXX_MACROS+=" -DTC_BROADCAST"
fi
if [[ "$APPLY_WAIT_ON_QUORUM" == "true" ]]; then
    EXTRA_CFLAGS+=" -DWAIT_ON_QUORUM"
    CXX_MACROS+=" -DWAIT_ON_QUORUM"
fi
if [[ "$APPLY_FAST_REPLY" == "true" ]]; then
    EXTRA_CFLAGS+=" -DFAST_REPLY"
    CXX_MACROS+=" -DFAST_REPLY"
fi

# Whether we should build/run eBPF side at all
USE_EBPF=false
if [[ "$APPLY_TC_BROADCAST" == "true" || "$APPLY_WAIT_ON_QUORUM" == "true" || "$APPLY_FAST_REPLY" == "true" ]]; then
    USE_EBPF=true
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Note: builds will run after we parse the config and set CLUSTER_SIZE

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Show last lines of local executable logs
show_local_exec_output() {
    local lines=${1:-50}
    if [[ -f /tmp/electrode.log ]]; then
        log_info "Last ${lines} lines of local /tmp/electrode.log (XDP user program):"
        tail -n "$lines" /tmp/electrode.log || true
    else
        log_warn "/tmp/electrode.log not found yet"
    fi
    if [[ -f /tmp/replica.log ]]; then
        log_info "Last ${lines} lines of local /tmp/replica.log (replica):"
        tail -n "$lines" /tmp/replica.log || true
    else
        log_warn "/tmp/replica.log not found yet"
    fi
}

# Show last lines of remote executable logs
show_remote_exec_output() {
    local ip=$1
    local lines=${2:-50}
    log_info "Fetching last ${lines} lines of logs from $ip..."
    ssh_exec "$ip" "if [ -f /tmp/electrode.log ]; then echo '--- /tmp/electrode.log (XDP user program) ---'; tail -n $lines /tmp/electrode.log; else echo '--- /tmp/electrode.log not found ---'; fi; if [ -f /tmp/replica.log ]; then echo '--- /tmp/replica.log (replica) ---'; tail -n $lines /tmp/replica.log; else echo '--- /tmp/replica.log not found ---'; fi" || true
}

# Extract IP addresses from config.txt
log_info "Parsing config.txt for replica IP addresses..."
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

log_info "Found ${#REPLICA_IPS[@]} replicas"

# Update CLUSTER_SIZE in electrode/electrode.h before building, based on number of replicas
update_cluster_size_define() {
    local count="$1"
    local hdr="electrode/electrode.h"
    if [[ ! -f "$hdr" ]]; then
        log_error "Header $hdr not found; cannot set CLUSTER_SIZE"
        exit 1
    fi
    # Warn if even-sized cluster (VR typically uses 2f+1)
    if (( count % 2 == 0 )); then
        log_warn "Cluster size $count from config is even; ensure this is intentional"
    fi
    # Replace the define line in-place
    if sed -i -E "s/^(#define[[:space:]]+CLUSTER_SIZE[[:space:]]+)[0-9]+/\\1${count}/" "$hdr"; then
        log_info "Set CLUSTER_SIZE to $count in $hdr"
    else
        log_error "Failed to update CLUSTER_SIZE in $hdr"
        exit 1
    fi
}

update_cluster_size_define "${#REPLICA_IPS[@]}"

# Now that CLUSTER_SIZE matches config, build components
if [[ "$USE_EBPF" == "true" ]]; then
    log_info "Recompiling eBPF code with EXTRA_CFLAGS='$EXTRA_CFLAGS'..."
    cd electrode && make clean && make EXTRA_CFLAGS="$EXTRA_CFLAGS"
    cd ..
else
    log_info "Skipping eBPF build because all optimization flags are disabled"
fi

log_info "Recompiling Replica code with CXXFLAGS='$CXX_MACROS'..."
make clean && make CXXFLAGS="$CXX_MACROS"

if [[ ! -f "$LOCAL_CONFIG_FILE" ]]; then
    log_warn "$LOCAL_CONFIG_FILE not found. Falling back to $CONFIG_FILE for remote deployment"
    LOCAL_CONFIG_FILE="$CONFIG_FILE"
fi

LOCAL_INTERFACE_IPS=()
while read -r addr; do
    LOCAL_INTERFACE_IPS+=("$addr")
done < <(ip -4 addr show "$NETWORK_INTERFACE" | awk '/inet / {print $2}' | cut -d'/' -f1)

if [[ ${#LOCAL_INTERFACE_IPS[@]} -eq 0 ]]; then
    log_warn "No local IPv4 addresses found for interface $NETWORK_INTERFACE"
fi

is_local_ip() {
    local target="$1"
    for candidate in "${LOCAL_INTERFACE_IPS[@]}"; do
        if [[ "$candidate" == "$target" ]]; then
            return 0
        fi
    done
    return 1
}

get_local_mac() {
    cat "/sys/class/net/$NETWORK_INTERFACE/address" 2>/dev/null | tr -d '\n' | tr '[:upper:]' '[:lower:]'
}

get_remote_mac() {
    local ip="$1"
    ssh_exec "$ip" "cat /sys/class/net/$NETWORK_INTERFACE/address" | tr -d '\r\n' | tr '[:upper:]' '[:lower:]'
}

generate_mac_config() {
    log_info "Generating $MAC_CONFIG_FILE with MAC addresses for interface $NETWORK_INTERFACE..."
    local tmp_file
    tmp_file=$(mktemp)
    if [[ -z "$tmp_file" ]]; then
        log_error "Failed to create temporary file for MAC config"
        exit 1
    fi

    for idx in "${!REPLICA_IPS[@]}"; do
        local ip="${REPLICA_IPS[$idx]}"
        local mac=""
        if is_local_ip "$ip"; then
            log_info "Fetching local MAC for replica $idx at $ip"
            mac=$(get_local_mac)
        else
            log_info "Fetching remote MAC for replica $idx at $ip"
            mac=$(get_remote_mac "$ip")
        fi

        if [[ -z "$mac" ]]; then
            log_error "Failed to retrieve MAC address for replica $idx at $ip"
            rm -f "$tmp_file"
            exit 1
        fi

        echo "$mac" >> "$tmp_file"
    done

    mv "$tmp_file" "$MAC_CONFIG_FILE"
    log_info "MAC addresses saved to $MAC_CONFIG_FILE"
}

ensure_known_hosts_file() {
    if [[ ! -d "$HOME/.ssh" ]]; then
        mkdir -p "$HOME/.ssh"
        chmod 700 "$HOME/.ssh"
    fi

    if [[ ! -f "$KNOWN_HOSTS_FILE" ]]; then
        touch "$KNOWN_HOSTS_FILE"
        chmod 600 "$KNOWN_HOSTS_FILE"
    fi
}

refresh_host_keys() {
    ensure_known_hosts_file

    for idx in "${!REPLICA_IPS[@]}"; do
        local ip="${REPLICA_IPS[$idx]}"

        log_info "Removing all host key entries for replica $idx at $ip"
        if ssh-keygen -f "$KNOWN_HOSTS_FILE" -R "$ip" >/dev/null 2>&1; then
            log_info "Removed existing host key for $ip"
        else
            log_info "No existing host key entry for $ip"
        fi
    done
}

# Function to run SSH command with password authentication
ssh_exec() {
    local ip=$1
    local command=$2
    
    # Use sshpass to provide password automatically
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "root@$ip" "$command"
}

# Function to run SSH command in background
ssh_exec_background() {
    local ip=$1
    local command=$2
    
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "root@$ip" "$command" &
}

# Function to copy file via SCP
scp_copy() {
    local ip=$1
    local local_file=$2
    local remote_path=$3
    
    sshpass -p "$PASSWORD" scp -o StrictHostKeyChecking=no "$local_file" "root@$ip:$remote_path"
}

# Safely copy a file that may be in use by first staging a temporary snapshot
scp_copy_safe() {
    local ip=$1
    local local_file=$2
    local remote_path=$3

    local tmp_file
    tmp_file=$(mktemp) || return 1
    # Create a temporary snapshot to avoid ETXTBUSY on the source binary
    if ! cp "$local_file" "$tmp_file"; then
        rm -f "$tmp_file"
        return 1
    fi
    local rc=0
    if ! scp_copy "$ip" "$tmp_file" "$remote_path"; then
        rc=1
    fi
    rm -f "$tmp_file"
    return $rc
}

# Check if sshpass is installed
if ! command -v sshpass &> /dev/null; then
    log_error "sshpass is not installed. Installing..."
    apt-get update && apt-get install -y sshpass
fi

refresh_host_keys

generate_mac_config

## Deploy to all replicas (treat all as remote)

# Deploy to each replica
for idx in "${!REPLICA_IPS[@]}"; do

    IP="${REPLICA_IPS[$idx]}"

    log_info "========================================"
    log_info "Deploying to Replica $idx at $IP"
    log_info "========================================"
    
    # Test SSH connection
    log_info "Testing SSH connection to $IP..."
    if ! ssh_exec "$IP" "echo 'Connection successful'"; then
        log_error "Failed to connect to $IP. Skipping..."
        continue
    fi

    # Stop irqbalance to keep replica CPU affinity stable
    if is_local_ip "$IP"; then
        log_info "Stopping irqbalance locally for replica $idx at $IP..."
        if systemctl is-active --quiet irqbalance; then
            if systemctl stop irqbalance; then
                log_info "irqbalance stopped locally"
            else
                log_warn "Failed to stop irqbalance locally; continuing"
            fi
        else
            log_info "irqbalance already inactive locally"
        fi

        log_info "Pinning IRQs for $NETWORK_INTERFACE to CPU0 locally..."
        local_irqs=$(grep -i "$NETWORK_INTERFACE" /proc/interrupts | cut -d: -f1 | tr -d ' ')
        if [[ -z "$local_irqs" ]]; then
            log_warn "No IRQs found locally for interface $NETWORK_INTERFACE"
        else
            pin_success=true
            for irq in $local_irqs; do
                if ! echo 1 > "/proc/irq/$irq/smp_affinity" 2>/dev/null; then
                    log_warn "Failed to pin IRQ $irq locally"
                    pin_success=false
                fi
            done
            if [[ "$pin_success" == true ]]; then
                log_info "Pinned IRQs locally: $local_irqs"
            fi
        fi
    else
        log_info "Stopping irqbalance on replica $idx at $IP..."
        if ! ssh_exec "$IP" "systemctl stop irqbalance"; then
            log_warn "Failed to stop irqbalance on $IP"
        fi

        log_info "Pinning IRQs for $NETWORK_INTERFACE to CPU0 on $IP..."
        pin_irq_command="IRQS=\$(grep -i '$NETWORK_INTERFACE' /proc/interrupts | cut -d: -f1 | tr -d ' '); if [ -z \"\$IRQS\" ]; then echo 'No IRQs found for $NETWORK_INTERFACE'; else pin_ok=true; for irq in \$IRQS; do if ! echo 1 > /proc/irq/\$irq/smp_affinity 2>/dev/null; then echo 'Failed to pin IRQ' \$irq; pin_ok=false; fi; done; if [ \"\$pin_ok\" = true ]; then echo 'Pinned IRQs:' \$IRQS; fi; fi"
        if ! ssh_exec "$IP" "$pin_irq_command"; then
            log_warn "Failed to pin IRQs on $IP"
        fi
    fi
    
    # Create remote directories if they don't exist
    log_info "Ensuring Electrode directories exist on $IP..."
    ssh_exec "$IP" "mkdir -p $REMOTE_DIR $REMOTE_DIR/$BPF_DIR $REMOTE_DIR/bench"

    # Stop any existing processes
    log_info "Stopping any existing replica and eBPF processes on $IP..."
    ssh_exec "$IP" "pkill -f './bench/replica' || true"
    ssh_exec "$IP" "pkill -f './$BPF_EXECUTABLE' || true"
    # Clean up pinned bpffs objects on remote
    ssh_exec "$IP" "find /sys/fs/bpf -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true"
    
    
    # Copy local_config.txt as config.txt to the remote machine
    log_info "Copying $LOCAL_CONFIG_FILE to $IP:$REMOTE_DIR/config.txt..."
    if ! scp_copy "$IP" "$LOCAL_CONFIG_FILE" "$REMOTE_DIR/config.txt"; then
        log_error "Failed to copy config file to $IP. Skipping..."
        continue
    fi

    log_info "Copying $MAC_CONFIG_FILE to $IP:$REMOTE_DIR/mac_config.txt..."
    if ! scp_copy "$IP" "$MAC_CONFIG_FILE" "$REMOTE_DIR/mac_config.txt"; then
        log_error "Failed to copy MAC config file to $IP. Skipping..."
        continue
    fi

    log_info "Copying $INTERFACE_CONFIG_FILE to $IP:$REMOTE_DIR/$INTERFACE_CONFIG_FILE..."
    if ! scp_copy "$IP" "$INTERFACE_CONFIG_FILE" "$REMOTE_DIR/$INTERFACE_CONFIG_FILE"; then
        log_error "Failed to copy interface config file to $IP. Skipping..."
        continue
    fi

    # Copy XDP executable, object file only if using eBPF
    if [[ "$USE_EBPF" == "true" ]]; then
        # Only remove old files if this is not a local IP (to avoid interfering with running local processes)
        if ! is_local_ip "$IP"; then
            log_info "Removing old XDP executable on $IP (if any) and copying new one..."
            ssh_exec "$IP" "rm -f $REMOTE_DIR/$BPF_DIR/$BPF_EXECUTABLE || true"
        fi
        log_info "Copying XDP executable to $IP:$REMOTE_DIR/$BPF_DIR/$BPF_EXECUTABLE..."
        if ! scp_copy_safe "$IP" "$BPF_DIR/$BPF_EXECUTABLE" "$REMOTE_DIR/$BPF_DIR/$BPF_EXECUTABLE"; then
            log_error "Failed to copy XDP executable to $IP. Skipping..."
            continue
        fi
        if ! is_local_ip "$IP"; then
            log_info "Removing old BPF object on $IP (if any) and copying new one..."
            ssh_exec "$IP" "rm -f $REMOTE_DIR/$BPF_OBJECT || true"
        fi
        log_info "Copying BPF object to $IP:$REMOTE_DIR/$BPF_OBJECT..."
        if ! scp_copy_safe "$IP" "$BPF_OBJECT" "$REMOTE_DIR/$BPF_OBJECT"; then
            log_error "Failed to copy BPF object to $IP. Skipping..."
            continue
        fi
    else
        log_info "Skipping XDP binary/object copy because eBPF is disabled"
    fi
    if ! is_local_ip "$IP"; then
        log_info "Removing old replica binary on $IP (if any) and copying new one..."
        ssh_exec "$IP" "rm -f $REMOTE_DIR/bench/replica || true"
    fi
    log_info "Copying replica binary to $IP:$REMOTE_DIR/bench/replica..."
    if ! scp_copy_safe "$IP" "bench/replica" "$REMOTE_DIR/bench/replica"; then
        log_error "Failed to copy replica binary to $IP. Skipping..."
        continue
    fi
    # Ensure executables are executable
    ssh_exec "$IP" "chmod +x $REMOTE_DIR/$BPF_DIR/$BPF_EXECUTABLE $REMOTE_DIR/bench/replica || true"
    
    
    if [[ "$USE_EBPF" == "true" ]]; then
        # Run eBPF code in background
        log_info "Starting eBPF code on $IP with interface $NETWORK_INTERFACE..."
        ssh_exec_background "$IP" "cd $REMOTE_DIR/$BPF_DIR && ./$BPF_EXECUTABLE > /tmp/electrode.log 2>&1"

        # Give eBPF time to initialize
        sleep 2

        log_info "Attaching TC filter on $IP for interface $NETWORK_INTERFACE..."
        ssh_exec "$IP" "tc qdisc add dev $NETWORK_INTERFACE clsact 2>/dev/null || true"
        ssh_exec "$IP" "tc filter add dev $NETWORK_INTERFACE egress bpf object-pinned /sys/fs/bpf/tc_broadcast 2>/dev/null || true"
    else
        log_info "Skipping eBPF start and TC attach on $IP because eBPF is disabled"
    fi
    
    # Run Replica with index
    log_info "Starting Replica $idx on $IP..."
    ssh_exec_background "$IP" "cd $REMOTE_DIR && taskset -c 1 ./bench/replica -c config.txt -m vr -i $idx > /tmp/replica.log 2>&1"
    
    log_info "Deployment to $IP completed!"
    # Show recent logs from remote processes
    show_remote_exec_output "$IP" 50
    sleep 1
done

log_info "========================================"
log_info "All deployments completed!"
log_info "========================================"

# Show status
log_info "Checking process status on all replicas..."
for idx in "${!REPLICA_IPS[@]}"; do
    IP="${REPLICA_IPS[$idx]}"
    log_info "Status for Replica $idx at $IP:"
    ssh_exec "$IP" "ps aux | grep -E '(\./$BPF_EXECUTABLE|./bench/replica)' | grep -v grep || echo 'No processes found'"
done
