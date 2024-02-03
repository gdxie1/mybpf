from bcc import BPF
from bcc.utils import printb

b = BPF(text="""
    TRACEPOINT_PROBE(block, block_rq_issue){
        bpf_trace_printk("Hello World"); 
        return 0;
    }
""")

while 1:
    try:
        b.trace_print()
    except KeyboardInterrupt:
        exit()
