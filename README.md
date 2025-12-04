# badfd

`badfd` is a powerful observability tool built using eBPF (Extended Berkeley Packet Filter). It is designed to monitor the openat() system call in the Linux kernel with extremely low overhead.

Its primary goal is to identify and record only the file open operations that are considered anomalous (the "bad FDs"), specifically:
1. openat() calls that fail (return a negative error code, e.g., -ENOENT).
2. openat() calls that exceed a predefined latency threshold (they are too slow).

## Core Advantages

### 1. Kernel-Side Filtering (Minimal Overhead)

Unlike traditional tracers that send all data to userspace for filtering, badfd-tracer executes its filtering logic directly within the kernel.
If an openat() operation is successful AND completes faster than the min_duration_ns threshold, the event is immediately discarded in the kernel.
This approach ensures the userspace program (e.g., a Go application consuming the data) only wakes up and processes data for genuine anomalies, drastically reducing CPU load.

### 2. Lazy Data Evaluation

To further optimize performance, the program avoids copying the full filename string (up to 256 bytes) when the system call begins (sys_enter_openat).
At the initial call, it only saves the pointer to the string in a temporary map (start_map).
Only if the operation fails or is too slow (sys_exit_openat), does the program "pay the cost" of safely reading the filename string from userspace memory before submitting the event.

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

```

### 2. Error Hunting
Show only failed open attempts, ignoring latency:

sudo ./badfd --err
PID      COMM             LATENCY    RESULT               FILE
1229     systemd          24.166µs   -ENOENT (No file)    /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/omarchy-battery-monitor.service/cgroup.procs
1229     systemd          9.117µs    -ENOENT (No file)    /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/omarchy-battery-monitor.service
1229     systemd          6.552µs    -ENOENT (No file)    /sys/fs/cgroup/pids.max
4452     10               7.855µs    -ENOENT (No file)    /usr/lib/systemd/glibc-hwcaps/x86-64-v3/libsystemd-core-258.2-2.so
4452     10               4.609µs    -ENOENT (No file)    /usr/lib/systemd/glibc-hwcaps/x86-64-v2/libsystemd-core-258.2-2.so
4452     10               7.825µs    -ENOENT (No file)    /usr/lib/systemd/libpam.so.0
604      systemd-journal  7.244µs    -ENOENT (No file)    /run/systemd/units/log-extra-fields:user@1000.service
4452     10               7.875µs    -ENOENT (No file)    /usr/lib/systemd/libseccomp.so.2
4452     10               6.632µs    -ENOENT (No file)    /usr/lib/systemd/libgcc_s.so.1
4452     10               7.013µs    -ENOENT (No file)    /usr/lib/systemd/libc.so.6
4452     10               6.893µs    -EACCES (Permission) /dev/kmsg
4452     10               4.428µs    -EACCES (Permission) /dev/console
4452     omarchy-battery  13.816µs   ERR(6)               /dev/tty
4452     omarchy-battery  3.357µs    -ENOENT (No file)    /usr/share/locale/en_US.UTF-8/LC_MESSAGES/bash.mo
4452     omarchy-battery  3.076µs    -ENOENT (No file)    /usr/share/locale/en_US.utf8/LC_MESSAGES/bash.mo
4452     omarchy-battery  3.987µs    -ENOENT (No file)    /usr/share/locale/en_US/LC_MESSAGES/bash.mo
4452     omarchy-battery  2.695µs    -ENOENT (No file)    /usr/share/locale/en.UTF-8/LC_MESSAGES/bash.mo
4452     omarchy-battery  2.655µs    -ENOENT (No file)    /usr/share/locale/en.utf8/LC_MESSAGES/bash.mo
4452     omarchy-battery  3.757µs    -ENOENT (No file)    /usr/share/locale/en/LC_MESSAGES/bash.mo
1229     systemd          10.059µs   -ENOENT (No file)    /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/omarchy-battery-monitor.service/cgroup.events
1229     systemd          7.013µs    -ENOENT (No file)    /run/user/1000/credentials/omarchy-battery-monitor.service
1229     systemd          6.111µs    -ENOENT (No file)    /run/user/1000/credentials/omarchy-battery-monitor.service
1389     Hyprland         6.052µs    -ENOENT (No file)    /usr/share/xkeyboard-config-2/rules/evdev.pre
1389     Hyprland         9.498µs    -ENOENT (No file)    /usr/share/xkeyboard-config-2/rules/evdev.post
2172     upowerd          3.988µs    -ENOENT (No file)    voltage_max_design
2172     upowerd          4.428µs    -ENOENT (No file)    voltage_max_design
2172     upowerd          3.116µs    -ENOENT (No file)    voltage_max_design
2172     upowerd          3.045µs    -ENOENT (No file)    voltage_max_design
2172     upowerd          3.186µs    -ENOENT (No file)    temp
2172     upowerd          3.026µs    -ENOENT (No file)    temp
1389     Hyprland         4.869µs    -ENOENT (No file)    /usr/share/xkeyboard-config-2/rules/evdev.pre
1389     Hyprland         4.919µs    -ENOENT (No file)    /usr/share/xkeyboard-config-2/rules/evdev.post
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

`badfd` uses eBPF CO-RE, Compile Once - Run Everywhere.

1. **Kernel Space**: A pair of tracepoints (`sys_enter_openat`, `sys_exit_openat`) correlate start/end times using a BPF Hash Map
2. **Filtering**: Logic resides in the kernel. Fast events are discarded before crossing the kernel/user boundary
3. **User Space**: A Go binary reads the RingBuffer, handles formatting, and provides the CLI

## License
MIT / GPL Dual Licensed
