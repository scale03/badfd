package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event_t bpf c/badfd.c

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Manual mapping of common Linux error codes.
// We avoid importing huge system libraries just for a few error strings.
// These are the most relevant ones for file I/O operations.
var errnoNames = map[int32]string{
	2:  "ENOENT (No file)",
	13: "EACCES (Permission)",
	1:  "EPERM (Op not permitted)",
	17: "EEXIST (File exists)",
	24: "EMFILE (Too many open files)",
}

func fmtErr(ret int32) string {
	if ret >= 0 {
		return "OK"
	}
	errCode := -ret // syscalls return negative values on error
	if name, ok := errnoNames[errCode]; ok {
		return fmt.Sprintf("-%s", name)
	}
	return fmt.Sprintf("ERR(%d)", errCode)
}

// JSON output structure.
// Defined externally to keep the main loop clean.
type LogEntry struct {
	Timestamp string `json:"ts"`
	Pid       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	LatencyNs uint64 `json:"lat_ns"`
	Result    string `json:"result"`
	File      string `json:"file"`
}

func main() {
	// CLI Flags
	msFlag := flag.Int("ms", 10, "Latency threshold in ms (0 = trace all)")
	errOnly := flag.Bool("err", false, "Trace only errors (ignore latency)")
	jsonFlag := flag.Bool("json", false, "Output in JSON format")
	flag.Parse()

	// Calculate threshold in nanoseconds.
	var limitNs uint64 = uint64(*msFlag) * 1000000
	if *errOnly {
		// Hack: If we only care about errors, set the latency threshold to
		// a very high value (1 hour). This ensures the kernel check
		// 'delta > limit' always fails, so only 'ret < 0' triggers events.
		limitNs = 3600 * 1000 * 1000 * 1000
	}

	// EXEC MODE logic
	args := flag.Args()
	var cmd *exec.Cmd
	if len(args) > 0 {
		cmd = exec.Command(args[0], args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Start(); err != nil {
			log.Fatalf("cmd start: %v", err)
		}
		// Avoid polluting stdout with logs if we are outputting JSON
		// meant to be parsed by machines.
		if !*jsonFlag {
			fmt.Printf("badfd: watching PID %d...\n", cmd.Process.Pid)
		}
	}

	// 1. System Setup
	// Allow the process to lock memory for eBPF maps.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	// 2. Load Spec
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("load bpf: %v", err)
	}

	// 3. Injection Config
	// Rewrite constants in the BPF bytecode *before* loading it into the kernel.
	// This acts like runtime patching, allowing us to configure the
	// latency threshold without recompiling the C code.
	if err := spec.RewriteConstants(map[string]interface{}{
		"min_duration_ns": uint64(limitNs),
	}); err != nil {
		log.Fatalf("rewrite constants: %v", err)
	}

	// 4. Load Objects
	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("load objects: %v", err)
	}
	defer objs.Close()

	// 5. Attach Tracepoints
	// We need to hook both ENTER (to start the timer) and EXIT (to stop it).
	kpEnter, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceEntry, nil)
	if err != nil {
		log.Fatalf("link enter: %v", err)
	}
	defer kpEnter.Close()

	kpExit, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.TraceExit, nil)
	if err != nil {
		log.Fatalf("link exit: %v", err)
	}
	defer kpExit.Close()

	// 6. Ringbuffer Reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Header: Print only if running in human-readable CLI mode.
	if !*jsonFlag {
		fmt.Printf("%-8s %-16s %-10s %-20s %s\n", "PID", "COMM", "LATENCY", "RESULT", "FILE")
	}

	// 7. Signal Handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if cmd != nil {
			cmd.Wait()            // Wait for child process
			sig <- syscall.SIGINT // Trigger shutdown
		}
	}()

	go func() {
		<-sig
		rd.Close()
	}()

	// 8. Event Loop
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		var event bpfEventT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		// Userspace PID filtering (Optional for Exec mode).
		// Note: Ideally, filtering should happen in kernel space using a PID map,
		// but for v1 doing it in userspace is simpler and acceptable.
		if cmd != nil && int(event.Pid) != cmd.Process.Pid {
			// continue
		}

		// Data preparation
		lat := time.Duration(event.DurationNs)
		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
		fname := string(bytes.TrimRight(event.Fname[:], "\x00"))
		res := fmtErr(event.Ret)

		if *jsonFlag {
			// --- JSON MODE (Machine Friendly) ---
			entry := LogEntry{
				Timestamp: time.Now().Format(time.RFC3339),
				Pid:       event.Pid,
				Comm:      comm,
				LatencyNs: event.DurationNs,
				Result:    res,
				File:      fname,
			}
			b, err := json.Marshal(entry)
			if err == nil {
				fmt.Println(string(b))
			}
		} else {
			// --- CLI MODE (Human Friendly) ---
			fmt.Printf("%-8d %-16s %-10s %-20s %s\n",
				event.Pid, comm, lat, res, fname)
		}
	}
}
