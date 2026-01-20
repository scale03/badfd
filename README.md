# badfd

`badfd` is a simple eBPF tool designed to detect file descriptor leaks by tracing the openat syscall. 
It monitors for ENOENT errors (file not found) and tracks operation latency, helping you identify inefficient file patterns, misconfigurations and potential leaks in real-time.


## Requirements
* Linux Kernel 5.8+ (BTF support enabled)
* Root privileges 
* Go 1.20+ 

## Installation
```bash
# Clone the repo
git clone https://github.com/scale03/badfd
cd badfd


make
```

## Usage

### Default mode, real time Error hunting 
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

## License
MIT / GPL Dual Licensed
