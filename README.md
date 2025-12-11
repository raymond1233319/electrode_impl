# Electrode Implementation

This repository contains an implementation of accelerating the Multi-Paxos Protocol using eBPF, as described in the paper ["Electrode: Accelerating Distributed Protocols with eBPF"](https://www.usenix.org/system/files/nsdi23-zhou.pdf) from NSDI 2023.

The implementation of the VR (Viewstamped Replication) protocol is located in the `vr/` directory and is based on [Speculative Paxos](https://github.com/UWSysLab/specpaxos). The eBPF code is located in the `electrode/` directory.

## Project Structure

- `vr/`: Contains the modified VR protocols.
- `electrode/`: Includes the eBPF code.

## Prerequisites

This project assumes you are running on **Ubuntu 22.04** with **Kernel 5.15**.

To run this project, you need to install the following dependencies:

- clang
- protobuf-compiler
- pkg-config
- libunwind-dev
- libssl-dev
- libprotobuf-dev
- libevent-dev
- libgtest-dev

## Getting Started

### 1. Install Dependencies

Run the following command to install the required packages (assuming Ubuntu/Debian):

```bash
sudo apt-get update
sudo apt-get install clang protobuf-compiler pkg-config libunwind-dev libssl-dev libprotobuf-dev libevent-dev libgtest-dev
```

### 2. Configuration

Modify `config.txt` to configure the replica information. The file format is as follows:

- The first line `f <number>` specifies the fault tolerance parameter $f$. The system can tolerate $f$ failures, requiring $2f+1$ replicas.
- The subsequent lines list the IP addresses and ports of the replicas in the format `replica <IP>:<PORT>`.

Example `config.txt`:
```text
f 1
replica 10.124.0.3:3939
replica 10.124.0.4:3939
replica 10.124.0.5:3939
```

### 3. Build and Deploy

Run the following scripts to prepare the kernel and deploy the application:

```bash
./prepare_kernel.sh
./deploy.sh
```

### 4. Benchmarking

Execute the benchmarking script to run the clients:

```bash
python3 run_bench_clients.py
```

## References

- **Paper**: [Electrode: Accelerating Distributed Protocols with eBPF](https://www.usenix.org/system/files/nsdi23-zhou.pdf) (NSDI 2023)
- **Base Implementation**: [Speculative Paxos](https://github.com/UWSysLab/specpaxos)