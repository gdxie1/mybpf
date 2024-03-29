#!/usr/bin/python
#
# This is a Hello World example that uses BPF_PERF_OUTPUT.

from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_RINGBUF_OUTPUT(events, 1<<4);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    //events.perf_submit(ctx, &data, sizeof(data));
    events.ringbuf_output( &data, sizeof(data), 0);

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    printb(bpfEntry"%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
        bpfEntry"Hello, perf_output!"))

# loop with callback to print_event
b["events"].open_ring_buffer(print_event)
while 1:
    try:
        b.ring_buffer_poll()
        print(".")
    except KeyboardInterrupt:
        exit()
