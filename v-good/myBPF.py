from bcc import BPF, USDTException
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import argparse
import re
import time
import pwd
from collections import defaultdict
from time import strftime, sleep
from UsdtInfo import UsdtInfo


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


# arguments
examples = """examples:
    ./execsnoop                      # trace all exec() syscalls
    ./execsnoop -x                   # include failed exec()s
    ./execsnoop -n main              # only print command lines containing "main"
"""
parser = argparse.ArgumentParser(
    description="Trace Python methods calling",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-n", "--name",
                    type=ArgString,
                    help="only print commands matching this name (regex), any arg")
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
    ucall_text = input_file .read()
args.name = 'factorial'
ucall_text = ucall_text.replace("METHODNAME", args.name)

# initialize BPF
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

# header
print("%-8s %-6s %-16s %-7s %-7s %3s %s" % ("UID", "TIME(ms)", "PCOMM", "PID", "PPID", "RET", "ARGS"))

class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

start_ts = time.time()
argv = defaultdict(list)


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
def print_event(cpu, data, size):
    event = b["events"].event(data)
    skip = False

    if event.type == EventType.EVENT_ARG:
        # argv[event.pid].append(event.argv +b":"+ str(len(argv[event.pid])).encode("ASCII"))
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        if event.retval != 0 and not args.fails:
            skip = True
        if args.name and not re.search(bytes(args.name), event.comm):
            skip = True
        if args.line and not re.search(bytes(args.line),
                                       b' '.join(argv[event.pid])):
            skip = True
        if args.quote:
            argv[event.pid] = [
                b"\"" + arg.replace(b"\"", b"\\\"") + b"\""
                for arg in argv[event.pid]
            ]

        if not skip:
            if args.time:
                printb(b"%-9s" % strftime("%H:%M:%S").encode('ascii'), nl="")
            if args.timestamp:
                printb(b"%-8.3f" % (time.time() - start_ts), nl="")
            if args.print_uid:
                printb(b"%-6d" % event.uid, nl="")
            ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
            ppid = b"%d" % ppid if ppid > 0 else b"?"
            argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
            printb(b"%-16s %-7d %-7s %3d %s" % (event.comm, event.pid,
                                                ppid, event.retval, argv_text))
        try:
            del (argv[event.pid])
        except Exception:
            pass


# use this dict to store the corresponding function latency
# now we only consider 1 process
processInfo = {}

# process event
def stat_event(cpu, data, size):
    event = b["events"].event(data)
    if event.type == EventType.EVENT_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        if event.retval == 0:
            # print(argv)
            # print("captured a process %s %s" % (event.comm, event.argv))
            argv_v = argv[event.pid]
            if argv_v and argv_v[0] == b'/usr/bin/python' and argv_v[1] == b'test.py':
                try:
                    usdtInfo = UsdtInfo(event.pid, ucall_text)
                    processInfo[event.pid] = usdtInfo
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
        # TODO   remove the accumulated argv if a process exit
        try:
            del (argv[event.pid])
        except Exception:
            pass

# def pull_data(count: int = 100):
#     for pid in bpfUsdtInfo:
#         # get the dict for a pid   bpfUsdtInfo[event.pid] = {'usdt': usdt, 'bpf': bpf, 'data': [xxx]}
#         pidData = bpfUsdtInfo.get(pid, None)
#         if pidData is not None and pidData['bpf'] is not None:
#             q_call = pidData['bpf'][b'q_call']
#             # Everytime, just pull 100 events
#             # the loop will break in advance if the queue is empty
#             data = pidData.get('data', [])
#             for i in range(count):
#                 try:
#                     call_t = q_call.pop()
#                     data.append(call_t)
#                 except KeyError:
#                     break
#             pidData['data'] = data
# loop with callback to print_event
b["events"].open_perf_buffer(stat_event)
exit_signaled = False
while 1:
    try:
        b.perf_buffer_poll(10)
        # sleep(args, interval)
        # wait the python script to run and populates some calling data
        sleep(1)
    except KeyboardInterrupt:
        exit_signaled = True
        break
    # test_pull_data()
    for usdtInfo in processInfo.values():
        curr_len = len(usdtInfo.trace_data)
        usdtInfo.pull_data()
        if curr_len < len(usdtInfo.trace_data):
        #     if there are new arrived call_t, output some information
            usdtInfo.print_last_call_t()

        # method_latency, unique_path = usdtInfo.survey_method(args.name)
        # print("Method latency:", method_latency)
        # print("Unique calling path", unique_path)

# pull all the rest data and merge data of different PID
latency = []
calling_path = set()
for usdtInfo in processInfo.values():
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

if len(latency) == 0:
    exit(0)
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
