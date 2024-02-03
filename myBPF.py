from bcc import BPF, USDTException
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import argparse
from collections import namedtuple
import re
import time
import pwd
from collections import defaultdict
from time import strftime, sleep
from UsdtInfo import UsdtInfo
from exitinfo import ExitInfo
# arguments
examples = """myBPF:
    ./myBPF                      # trace all default method 'factorial'
    ./myPBF -n main              # only print method  containing "main"
"""
parser = argparse.ArgumentParser(
    description="Trace Python methods calling",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-n", "--name",
                    type=ArgString,
                    help="only print method matching this name (regex), any arg")
parser.add_argument("--max-args", default="20",
                    help="maximum number of arguments parsed and displayed, defaults to 20")
parser.add_argument("--cgroupmap",
                    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
                    help="trace mount namespaces in this BPF map only")

args = parser.parse_args()


# open execve probe program
with open('pystart.c', 'r') as input_file:
    bpf_text = input_file.read()
bpf_text = bpf_text.replace("MAXARG", args.max_args)
bpf_text = filter_by_containers(args) + bpf_text

# open usdt probe program
with open('ucall.c', 'r') as input_file:
    ucall_text = input_file.read()
    # 'factorial'
args.name = "factorial"
ucall_text = ucall_text.replace("METHODNAME", args.name)

# open process exit probe program
with open('process_exit.c', 'r') as input_file:
    pexit_text = input_file.read()

# initialize BPF for tracing the entry of process
bpfEntry = BPF(text=bpf_text)
execve_fnname = bpfEntry.get_syscall_fnname("execve")
bpfEntry.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
bpfEntry.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")


class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

# BPF for tracing the exit of process
bpfExit = BPF(text=pexit_text)

# Dict to store each traced process and its USDT info
# not all traced pids are listed in the dict. as some python process last very short time
# and terminates, which is impossible to attach an USDT probe
bpfUsdtInfo = {}
entryInfo = {}
exitinfo = ExitInfo(bpfExit)


def parse_uid(user):
    try:
        result = int(user)
    except ValueError:
        try:
            user_info = pwd.getpwnam(user)
        except KeyError:
            raise argparse.ArgumentTypeError(
                "{0!r} is not valid UID or user entry".format(user))
        else:
            return user_info.pw_uid
    else:
        # Maybe validate if UID < 0 ?
        return result


# This is best-effort PPID matching. Short-lived processes may exit
# before we get a chance to read the PPID.
# This is a fallback for when fetching the PPID from task->real_parent->tgip
# returns 0, which happens in some kernel versions.
def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0


# process event
def stat_event(cpu, data, size):
    event = bpfEntry["events"].event(data)
    if event.type == EventType.EVENT_ARG:
        argv[event.pid].append(event.argv)
        # keep entry event for further usage
        entryInfo[event.pid] = event
    elif event.type == EventType.EVENT_RET:
        if event.retval == 0:
            # print(argv)
            # print("captured a process %s %s" % (event.comm, event.argv))
            argv_v = argv[event.pid]
            # TODO change checking /usr/bin/python to checking comm
            if argv_v and len(argv_v) > 1 and argv_v[0] == b'/usr/bin/python' and argv_v[1] == b'test.py':
                # no matter if we are able to create a UsdtInfo, we need to keep those pid
                # as some python script may terminate in very short time.
                exitinfo.addPid(event.pid)
                try:
                    usdtInfo = UsdtInfo(event.pid, ucall_text)
                    bpfUsdtInfo[event.pid] = usdtInfo
                    printb(b"%-6d" % event.uid, nl="")
                    printb(b"%-9s" % strftime("%H:%M:%S").encode('ascii'), nl="")
                    ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
                    ppid = b"%d" % ppid if ppid > 0 else b"?"
                    argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
                    printb(b"%-16s %-7d %-7s %3d %s" % (event.comm, event.pid,
                                                        ppid, event.retval, argv_text))
                    # print(f"captured python test.py process {event.pid}")
                except USDTException as e:
                    pass
                except Exception as e:
                    pass
        try:
            del (argv[event.pid])
        except Exception:
            pass


# header
print("%-8s %-6s %-16s %-7s %-7s %3s %s" % ("UID", "TIME(ms)", "PCOMM", "PID", "PPID", "RET", "ARGS"))

argv = defaultdict(list)
bpfEntry["events"].open_perf_buffer(stat_event)

exit_signaled = False
# while 1:
#     try:
#         bpfEntry.perf_buffer_poll(10)
#         # wait the python script to run and populates some calling data
#         sleep(1)
#     except KeyboardInterrupt:
#         exit_signaled = True
#         break
for i in range(50):
    try:
        bpfEntry.perf_buffer_poll(10)
        # wait the python script to run and populates some calling data
        sleep(1)
    except KeyboardInterrupt:
        exit_signaled = True
        break

    curr_len = len(exitinfo.pidExitList)
    exitinfo.pull_data()
    if curr_len < len(exitinfo.pidExitList):
        #     if there are new arrived exit_e, output some information
        exitinfo.print_last_event()

    # for exit_e in exitinfo.pidExitList:
    #     print(exit_e.task)

    for usdtInfo in bpfUsdtInfo.values():
        curr_len = len(usdtInfo.trace_data)
        usdtInfo.pull_data()
        if curr_len < len(usdtInfo.trace_data):
            #     if there are new arrived call_t, output some information
            usdtInfo.print_last_event()


# pull all the rest data and merge data of different PID
latency = []
calling_path = set()
for usdtInfo in bpfUsdtInfo.values():
    # try to pull all remaining data
    usdtInfo.pull_data(10240)
    print("\nPID %d -------------------" % usdtInfo.pid)
    # get the dict for a pid   bpfUsdtInfo[event.pid] = {'usdt': usdt, 'bpf': bpf, 'data': [xxx]}
    # for call_t in usdtInfo.trace_data:
    #     print(call_t.clazz.decode('ascii'), call_t.method.decode('ascii'), call_t.depth, call_t.ts)
    method_latency, unique_path = usdtInfo.survey_method(args.name)
    # merging the return data
    latency.extend(method_latency)
    calling_path = calling_path.union(unique_path)
    print("latency", len(latency))
    print("calling_path", calling_path)

if len(latency) != 0:
    avg_latency = sum(latency) / len(latency)
    max_latency = max(latency)
    min_latency = min(latency)
    print("Statics for the function %s" % args.name)
    print("All the spending time of calling:", latency)
    print("Total count of traced calling:", len(latency))

    print("%-16s %-16s %-16s" % ("Average Lat(us)", "Max Lat(us)", "Min Lat(us)"))
    print("%12.4f %12.4f %12.4f" % (avg_latency, max_latency, min_latency))
    for u_path in calling_path:
        print(u_path)

# output the failure and successful python process
calling_yes, calling_no, pid_lattency = exitinfo.survey()
count_yes = len(calling_yes)
count_no = len(calling_no)

print("Statistics of the successful ratio of calling")
print("Total count of traced process:", count_yes+count_no)
print("Successful ratio of calling:", count_yes/(count_yes+count_no))
print("Latency of each calling:\n")
print(pid_lattency)


