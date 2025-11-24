//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// ============================================================================
// CONFIGURATION
// ============================================================================

// Latency threshold (Default: 0ns, trace everything).
// We place this in the .rodata section to allow userspace (Go) to rewrite
// this constant before loading the program into the kernel.
// DESIGN NOTE: Using a constant here instead of a BPF map lookup saves
// critical CPU cycles in the execution hot path.
__attribute__((section(".rodata"))) volatile const u64 min_duration_ns = 0;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// Temporary state saved between sys_enter and sys_exit.
struct start_req_t {
    u64 ts;         // Timestamp (ns)
    u64 fname_ptr;  // Pointer to the filename string in userspace
};

// Final event sent to userspace via RingBuffer.
struct event_t {
    u32 pid;
    s32 ret;         // Return value (e.g., -ENOENT)
    u64 duration_ns; // Latency
    u8 comm[16];     // Process name
    u8 fname[256];   // Filename
};

// Force BTF type generation for the event struct.
const struct event_t *__type_hack __attribute__((unused));

// ============================================================================
// BPF MAPS
// ============================================================================

// State Map (Key: PID, Value: start_req_t).
// We use a HASH map because PIDs are sparse.
// Max entries 10240 allows tracking 10k concurrent open() calls.
// If the system exceeds this, we drop events rather than crashing memory.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct start_req_t);
} start_map SEC(".maps");

// Output RingBuffer.
// 16MB buffer. RAM is cheap, losing forensic data is expensive.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); 
} events SEC(".maps");


// ============================================================================
// TRACEPOINT: SYS_ENTER_OPENAT
// Triggered when a process CALLS openat()
// ============================================================================
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_entry(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct start_req_t req = {};

    // 1. Capture start time (monotonic clock)
    req.ts = bpf_ktime_get_ns();

    // 2. Capture the POINTER to the filename.
    // LAZY EVALUATION: We DO NOT read the string bytes yet.
    // Copying 256 bytes for every open() would burn CPU bandwidth unnecessarily
    // if the operation turns out to be fast or successful. We wait.
    // ctx->args[1] is the 2nd argument of openat: (dfd, *filename, flags...)
    req.fname_ptr = ctx->args[1];

    // 3. Save state. Overwriting is acceptable (last write wins).
    bpf_map_update_elem(&start_map, &pid, &req, BPF_ANY);

    return 0;
}

// ============================================================================
// TRACEPOINT: SYS_EXIT_OPENAT
// Triggered when openat() RETURNS (with a result or error)
// ============================================================================
SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit(struct trace_event_raw_sys_exit *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct start_req_t *req;
    struct event_t *e;
    u64 now, delta;

    // 1. Retrieve the state saved at entry
    req = bpf_map_lookup_elem(&start_map, &pid);
    if (!req) {
        // Missed entry? Possible if badfd started while open() was 
        // already in progress. We ignore this edge case.
        return 0;
    }

    // 2. Calculate latency
    now = bpf_ktime_get_ns();
    delta = now - req->ts;

    // 3. ANOMALY DETECTION LOGIC (The Core of badfd)
    // We filter strictly in the kernel to avoid waking up userspace.
    // We only care if:
    // A) The syscall FAILED (ret < 0)
    // B) The latency exceeded our configured threshold
    if (ctx->ret >= 0 && delta < min_duration_ns) {
        // Happy path: fast and successful.
        // Clean up map and exit immediately. Zero overhead.
        bpf_map_delete_elem(&start_map, &pid);
        return 0;
    }

    // --- IF WE ARE HERE, WE FOUND A "BAD FD" ---

    // 4. Reserve space in RingBuffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // Buffer full? Drop the event.
        // It's better to lose a log than to block the kernel.
        bpf_map_delete_elem(&start_map, &pid);
        return 0;
    }

    // 5. Populate data
    e->pid = pid;
    e->ret = ctx->ret;
    e->duration_ns = delta;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 6. PAY THE COST: Read the filename string now.
    // We use the pointer we saved earlier.
    bpf_probe_read_user_str(&e->fname, sizeof(e->fname), (const char *)req->fname_ptr);

    // 7. Submit to userspace
    bpf_ringbuf_submit(e, 0);

    // 8. Cleanup
    bpf_map_delete_elem(&start_map, &pid);

    return 0;
}
