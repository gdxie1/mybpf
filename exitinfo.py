
# Define a class to store ps state(0 normal; 1 exit) and exit value
class PsState:
    def __init__(self ):
        self.exit_e = None
        self.state = 0
        self.ret = None



class ExitInfo(object):
    # traced pid. including those terminated with error, e.g failed to load the script
    def __init__(self, bpf):
        self.bpf = bpf
        self.pidDict = {}
        self.pidExitList = []
    def addPid(self, pid):
        """ Add the PID to the dict when a new process is traced"""
        if pid in self.pidDict:
            return
        self.pidDict[pid] = PsState()

    def print_last_event(self):
        if len(self.pidExitList) == 0:
            return
        exit_e = self.pidExitList[-1]
        print(f"Process exit event traced: PID is {exit_e.pid}, Command name is {exit_e.task.decode('ascii')}, "
              f"Return Value is {exit_e.exit_code}")


    def pull_data(self, count=100):
        """Extract exit process event from BPE QUEUE and then change the state of PsState in pidDict"""
        q_exit_process = self.bpf[b'exit_e']
        for i in range(count):
            try:
                exit_e = q_exit_process.pop()
                # keep all exit_e for debug
                if exit_e.pid in self.pidDict.keys():
                    # we only add those traced python process
                    self.pidExitList.append(exit_e)
                    # update the state of exit
                    self.pidDict[exit_e.pid].exit_e = exit_e
                    self.pidDict[exit_e.pid].state = 1
                    self.pidDict[exit_e.pid].ret = exit_e.exit_code
            except KeyError:
                break

    def survey(self):
        """Extract captured exited process and its state from pidDict"""
        success_cases = []
        failure_cases = []
        latency = []
        for pid, pstate in self.pidDict.items():
            latency.append((pid, (self.pidDict[pid].exit_e.exit_time - self.pidDict[pid].exit_e.start_time)/1000))
            if pstate.ret == 0:
                success_cases.append(pstate)
            else:
                failure_cases.append(pstate)

        return success_cases, failure_cases, latency
