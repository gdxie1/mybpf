from bcc import BPF
from bcc.utils import printb

prog = '''
#include <uapi/linux/ptrace.h>

BPF_HASH(last); 

int do_trace(struct pt_regs *ctx) {
    u64 ct = 1,  *csp, key_t=0, key_c=1;
     
    csp = last.lookup(&key_c);
    if(csp != NULL){
        *csp +=1;
        last.update(&key_c, csp);
    }else{
        ct = 1; 
        last.update(&key_c, &ct);
    }
    csp = last.lookup(&key_c); 
    if(csp != NULL){
        bpf_trace_printk("%d\\n", *csp);
    }
    return 0; 
}
'''
bpf = BPF(text=prog)
bpf.attach_kprobe(event=bpf.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's ... Ctrl-C to quit")

# format output
start = 0
while 1:
    try:
        (task, pid, cpu, flags, ts, ms) = bpf.trace_fields()
        printb(bpfEntry"Count of sync is %s" % ms)
    except KeyboardInterrupt:
        exit()



