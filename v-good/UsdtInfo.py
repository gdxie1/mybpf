from bcc import BPF, USDT


class UsdtInfo(object):
    """ Class to manage the USDT probe and its returned data"""

    def __init__(self, pid, src_text):
        self.pid = pid
        self.usdt = USDT(pid=pid)
        self.usdt.enable_probe_or_bail("function__entry", "trace_entry")
        self.usdt.enable_probe_or_bail("function__return", "trace_return")
        self.bpf = BPF(text=src_text, usdt_contexts=[self.usdt])
        self.trace_data = []

    def print_last_call_t(self):
        if len(self.trace_data) == 0:
            return
        call_t = self.trace_data[-1]
        print(f"PID:{self.pid:-8d}'s calling traced:{call_t.method.decode('ascii')}")

    def survey_method(self, method_name):
        """ Returns the latency of the method being called"""
        method_span = []
        i_entry = i_ret = -1
        for i, call_t in enumerate(self.trace_data):
            if call_t.method == method_name.encode("ascii") and call_t.dir == 0:
                i_entry = i
            if call_t.method == method_name.encode("ascii") and call_t.dir == 1 and i_entry != -1:
                i_ret = i
                method_span.append((i_entry, i_ret))

        method_latency = []
        unique_path = set()
        # for each calling path, e.g. entry and return
        for i_entry, i_ret in method_span:
            latency = self.trace_data[i_ret].ts - self.trace_data[i_entry].ts
            method_latency.append(latency/1000)
            call_path = ""
            i = i_entry
            while i < i_ret +1:
                call_t = self.trace_data[i]
                depth = call_t.depth
                if call_t.dir == 0 and i+1 <= i_ret and self.trace_data[i+1].dir == 1:
                    path ="  " * (depth - 1) + "-> <-" +call_t.method.decode('utf-8', 'replace') + "\n"
                    call_path += path
                    i += 2
                    continue
                direction = "<- " if call_t.dir else "-> "
                path = "  " * (depth - 1) + direction + call_t.method.decode('utf-8', 'replace') + "\n"
                call_path += path
                i+=1
            unique_path.add(call_path)

            # for i in range(i_entry, i_ret+1):
            #     call_t = self.trace_data[i]
            #     depth =call_t.depth
            #     if call_t.dir == 0 and i+1 <= i_ret and self.trace_data[i+1].dir == 1:
            #
            #     direction = "<- " if call_t.dir else "-> "
            #     path = "  " * (depth - 1) + direction + call_t.method.decode('utf-8', 'replace') + "\n"
            #     call_path += path
        return method_latency, unique_path

    def pull_data(self, count=100):
        """ Pulls data from the queue in kernel"""
        q_call = self.bpf[b'q_call']
        # Everytime, just pull 100 events
        # the loop will break in advance if the queue is empty
        for i in range(count):
            try:
                call_t = q_call.pop()
                self.trace_data.append(call_t)
            except KeyError:
                break
