#!/usr/bin/python
#
# This is a Hello World example that formats output as fields.

from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

int do_ret_sys_execve(struct pt_regs *ctx) {
    bpf_trace_printk("%d\\n",  PT_REGS_RC(ctx));
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
# execve_fnname = b.get_syscall_fnname("execve")

b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="do_ret_sys_execve")

# header
print("%-18s %-28s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-20s %-6d %s" % (ts, task, pid, msg))
