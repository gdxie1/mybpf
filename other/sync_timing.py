
#!/usr/bin/python
#
# sync_timing.py    Trace time between syncs.
#                   For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing time between events.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(last);
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];    
};

BPF_PERF_OUTPUT(events);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;
    
    struct data_t data = {};
    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            //bpf_trace_printk("%d\\n", delta / 1000000);
            data.pid = bpf_get_current_pid_tgid();
            data.ts = delta / 1000000;        
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            events.perf_submit(ctx, &data, sizeof(data)); 
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    // if it's the first time, the program will go here directly. 
    // even we use address as parameter, the hash table will store its value, I guess. 
    last.update(&key, &ts);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("%-27s %-16s %-6s %s" % ("last TIME(s) ago", "COMM", "PID", "MESSAGE"))
print("Tracing for quick sync's... Ctrl-C to end")

def print_event(cup, data, size):
    event = b["events"].event(data)
    # print(bpfEntry"%-18.9f %-16s %-6d %s" % (event.ts, event.comm, event.pid, bpfEntry"Hello, pef_output"))
    msg_output = bpfEntry"%-18.9f %-16s %-6d %s" % (event.ts, event.comm, event.pid, bpfEntry"Hello, pef_output")
    print(msg_output.decode('ASCII'))

# connect the print_event with the events inside the buffer
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
