#!/usr/bin/python
#
# disksnoop.py	Trace block device I/O: basic version of iosnoop.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Aug-2015	Brendan Gregg	Created this.

from bcc import BPF
from bcc.utils import printb

REQ_WRITE = 1  # from include/linux/blk_types.h

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
//#include <linux/sched.h>
#include <linux/blk-mq.h>
struct data_t {
    u32 data_len;
    u32 latency;
    u32 flag;
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_HISTOGRAM(dist);
BPF_HASH(start, struct request *);

void trace_start(struct pt_regs *ctx, struct request *req) {
	// stash start timestamp by request ptr
	u64 ts = bpf_ktime_get_ns();
	start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
	u64 *tsp, delta;
	
    struct data_t data = {};
	tsp = start.lookup(&req);
	if (tsp != 0) {
		delta = bpf_ktime_get_ns() - *tsp;
//		bpf_trace_printk("%d %x %d\\n", req->__data_len,
//		    req->cmd_flags, delta / 1000);
        data.latency = delta / 1000;
        data.pid = bpf_get_current_pid_tgid();
        data.ts = bpf_ktime_get_ns();
        data.flag = req->cmd_flags;
        data.data_len = req->__data_len;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        
        events.perf_submit(ctx, &data, sizeof(data));
		dist.increment(bpf_log2l(delta/1000));
		start.delete(&req);
	}
}
""")

if BPF.get_kprobe_functions(bpfEntry'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
if BPF.get_kprobe_functions(bpfEntry'__blk_account_io_done'):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_completion")
else:
    b.attach_kprobe(event="blk_mq_end_request", fn_name="trace_completion")

# header
print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))

def print_event(cpu, data, size):
    """print the event that contains the data"""

    event = b["events"].event(data)
    bytes_s = event.data_len;
    if event.flag & REQ_WRITE:
        type_s = bpfEntry"W"
    elif bytes_s == "0":  # see blk_fill_rwbs() for logic
        type_s = bpfEntry"M"
    else:
        type_s = bpfEntry"R"
    la = event.latency/1000
    ts = event.ts/1000000
    pid = event.pid
    task = event.comm
    printb(bpfEntry"%-18.9f %-2s %-7d %-8.2f %-10d %s" % (ts, type_s, bytes_s, la, pid, task))
    # printb(bpfEntry"%-18.9f %-2s" % (ts, type_s))

b["events"].open_perf_buffer(print_event)
# format output
while 1:
    try:
        b.perf_buffer_poll()
        # # (task, pid, cpu, flags, ts, msg) = bpfEntry.trace_fields()
        # # (bytes_s, bflags_s, us_s) = msg.split()
        #
        # if int(bflags_s, 16) & REQ_WRITE:
        #     type_s = bpfEntry"W"
        # elif bytes_s == "0":  # see blk_fill_rwbs() for logic
        #     type_s = bpfEntry"M"
        # else:
        #     type_s = bpfEntry"R"
        # ms = float(int(us_s, 10)) / 1000
        #
        # printb(bpfEntry"%-18.9f %-2s %-7s %8.2f %-10d %s" % (ts, type_s, bytes_s, ms, pid, task))
    except KeyboardInterrupt:
        break
        # exit()
        # print()
        # exit()

b["dist"].print_log2_hist("latency")
