from bcc import  BPF, USDT


class UsdtInfo(object):
    """ Class to manage the USDT probe and its returned data"""
    def __init__(self, pid, src_text):
        self.usdt = USDT(pid=pid)
        self.usdt.enable_probe_or_bail("function__entry", "trace_entry")
        self.usdt.enable_probe_or_bail("function__return", "trace_return")
        self.bpf = BPF(src_file=src_text, usdt_contexts=[self.usdt])
        self.trace_data = []

    def pull_data(self, count):
        """ Pulls data from the queue in kernel"""
        q_call = self.bpf[bpfEntry'q_call']
        # Everytime, just pull 100 events
        # the loop will break in advance if the queue is empty
        for i in range(count):
            try:
                call_t = q_call.pop()
                self.trace_data.append(call_t)
            except KeyError:
                break

