from bcc import BPF

# BPF program code
bpf_program = """
#include <uapi/linux/ptrace.h>

// kprobe for do_execve
int kprobe__do_execve(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("Python script launched (pid=%d, comm=%s)\\n", bpf_get_current_pid_tgid(), comm);
    return 0;
}

// kretprobe for do_exit
int kretprobe__do_exit(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("Python script exited (pid=%d, comm=%s)\\n", bpf_get_current_pid_tgid(), comm);
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_program)

# Attach kprobes
b.attach_kprobe(event="do_execve", fn_name="kprobe__do_execve")
b.attach_kretprobe(event="do_exit", fn_name="kretprobe__do_exit")

# Print trace messages
while True:
    try:
        print(b.trace_fields())
    except KeyboardInterrupt:
        break