# badfd
Syscall observability via subtraction.

**"Silence is the default output of a healthy system."**

`badfd` is an eBPF-based tool designed to detect I/O anomalies on Linux systems. Unlike standard tracers which show all traffic, `badfd` is designed to show only problems.

It sits silently in the kernel and only emits events when:
1. A file operation takes too long (Latency)
2. A file operation fails (Error)

`badfd` acts as a high-pass filter for filesystem interactions: if an operation is fast and successful, userspace is never notified (Zero Overhead).

## Requirements
* Linux Kernel 5.8+ (BTF support enabled)
* Root privileges (to load eBPF programs)
* Go 1.20+ (for building)

## Installation
```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/badfd
cd badfd

# Build (requires clang and kernel headers)
make
```

## Usage

### 1. Latency Hunting (Default)
Show only `open()` syscalls that take longer than 10ms:
```bash
sudo ./badfd --ms 10
```

### 2. Error Hunting
Show only failed open attempts (e.g., missing config, permission denied), ignoring latency:
```bash
sudo ./badfd --err
```

### 3. Execution Wrapper
Launch a command and trace only its anomalies (and its children):
```bash
sudo ./badfd --err -- python3 my_broken_script.py
```

### 4. JSON Output (Pipeline Mode)
Emit structured JSON for logging pipelines (Elastic, Fluentd, etc.):
```bash
sudo ./badfd --json --ms 50
```

## Architecture

`badfd` uses eBPF CO-RE (Compile Once - Run Everywhere):

1. **Kernel Space**: A pair of tracepoints (`sys_enter_openat`, `sys_exit_openat`) correlate start/end times using a BPF Hash Map
2. **Filtering**: Logic resides in the kernel. Fast events are discarded before crossing the kernel/user boundary
3. **User Space**: A Go binary reads the RingBuffer, handles formatting, and provides the CLI

## License
MIT / GPL Dual Licensed
