# badfd

`badfd` is a simple eBPF tool designed to detect file descriptors leaks by tracing the openat syscall. 
Allowing you to observe ENOENT errors (file not found) , EACCES (permission denied) and IO latency. 
### You can use it to: 
* Hunt misconfigurations.
* Debug Runtime and IO problems.
* Discover potential leaks in real-time.


### Requirements
* Linux Kernel 5.8+ (BTF support enabled)
* Root privileges 
* Go 1.20+ 

### Installation
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
