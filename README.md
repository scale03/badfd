# badfd

`badfd` is a powerful observability tool built using eBPF (Extended Berkeley Packet Filter). It is designed to monitor the openat() system call in the Linux kernel with extremely low overhead.

Its primary goal is to identify and record only the file open operations that are considered anomalous (the "bad FDs"), specifically:
1. openat() calls that fail (return a negative error code, e.g., -ENOENT).
2. openat() calls that exceed a predefined latency threshold (they are too slow).


## Requirements
* Linux Kernel 5.8+ (BTF support enabled)
* Root privileges 
* Go 1.20+ 

## Installation
```bash
# Clone the repo
git clone https://github.com/scale03/badfd
cd badfd

# Build (requires clang and kernel headers)
make
```

## Usage

### Default mode, Error hunting
```

sudo ./badfd --err

```


### Launch a command and trace only its anomalies (and its children):
```bash
sudo ./badfd --err -- python3 my_broken_script.py
```

### JSON Output (Pipeline Mode)
Emit structured JSON for logging pipelines (Elastic, Fluentd, etc.):
```bash
sudo ./badfd --json --ms 50
```

## Architecture

`badfd` uses eBPF CO-RE, Compile Once - Run Everywhere.

1. **Kernel Space**: A pair of tracepoints (`sys_enter_openat`, `sys_exit_openat`) correlate start/end times using a BPF Hash Map
2. **Filtering**: Logic resides in the kernel. Fast events are discarded before crossing the kernel/user boundary
3. **User Space**: A Go binary reads the RingBuffer, handles formatting, and provides the CLI

## License
MIT / GPL Dual Licensed
