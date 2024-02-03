from bcc import BPF, USDT, utils
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import argparse
import re
import time
import pwd
from collections import defaultdict
from time import strftime, sleep
from os import get_terminal_size


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
    ./execsnoop -T                   # include time (HH:MM:SS)
    ./execsnoop -P 181               # only trace new processes whose parent PID is 181
    ./execsnoop -U                   # include UID
    ./execsnoop -u 1000              # only trace UID 1000
    ./execsnoop -u user              # get user UID and trace only them
    ./execsnoop -t                   # include timestamps
    ./execsnoop -q                   # add "quotemarks" around arguments
    ./execsnoop -n main              # only print command lines containing "main"
    ./execsnoop -l tpkg              # only print command where arguments contains "tpkg"
    ./execsnoop --cgroupmap mappath  # only trace cgroups in this BPF map
    ./execsnoop --mntnsmap mappath   # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Trace exec() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--time", action="store_true",
                    help="include time column on output (HH:MM:SS)")
parser.add_argument("-t", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("-x", "--fails", action="store_true",
                    help="include failed exec()s")
parser.add_argument("--cgroupmap",
                    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
                    help="trace mount namespaces in this BPF map only")
parser.add_argument("-u", "--uid", type=parse_uid, metavar='USER',
                    help="trace this UID only")
parser.add_argument("-q", "--quote", action="store_true",
                    help="Add quotemarks (\") around arguments."
                    )
parser.add_argument("-n", "--name",
                    type=ArgString,
                    help="only print commands matching this name (regex), any arg")
parser.add_argument("-l", "--line",
                    type=ArgString,
                    help="only print commands where arg contains this line (regex)")
parser.add_argument("-U", "--print-uid", action="store_true",
                    help="print UID column")
parser.add_argument("--max-args", default="20",
                    help="maximum number of arguments parsed and displayed, defaults to 20")
parser.add_argument("-P", "--ppid",
                    help="trace this parent PID only")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u32 uid;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    UID_FILTER

    if (container_should_be_filtered()) {
        return 0;
    }

    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    PPID_FILTER

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);
    
    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    if (container_should_be_filtered()) {
        return 0;
    }

    struct data_t data = {};
    struct task_struct *task;

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    UID_FILTER

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = uid;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    PPID_FILTER

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

bpf_text = bpf_text.replace("MAXARG", args.max_args)

if args.uid:
    bpf_text = bpf_text.replace('UID_FILTER',
                                'if (uid != %s) { return 0; }' % args.uid)
else:
    bpf_text = bpf_text.replace('UID_FILTER', '')

if args.ppid:
    bpf_text = bpf_text.replace('PPID_FILTER',
                                'if (data.ppid != %s) { return 0; }' % args.ppid)
else:
    bpf_text = bpf_text.replace('PPID_FILTER', '')

bpf_text = filter_by_containers(args) + bpf_text
if args.ebpf:
    print(bpf_text)
    exit()

# initialize BPF
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

# header
if args.time:
    print("%-9s" % ("TIME"), end="")
if args.timestamp:
    print("%-8s" % ("TIME(s)"), end="")
if args.print_uid:
    print("%-6s" % ("UID"), end="")
print("%-16s %-7s %-7s %3s %s" % ("PCOMM", "PID", "PPID", "RET", "ARGS"))


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
        # argv[event.pid].append(event.argv +bpfEntry":"+ str(len(argv[event.pid])).encode("ASCII"))
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        if event.retval != 0 and not args.fails:
            skip = True
        if args.name and not re.search(bytes(args.name), event.comm):
            skip = True
        if args.line and not re.search(bytes(args.line),
                                       bpfEntry' '.join(argv[event.pid])):
            skip = True
        if args.quote:
            argv[event.pid] = [
                bpfEntry"\"" + arg.replace(bpfEntry"\"", bpfEntry"\\\"") + bpfEntry"\""
                for arg in argv[event.pid]
            ]

        if not skip:
            if args.time:
                printb(bpfEntry"%-9s" % strftime("%H:%M:%S").encode('ascii'), nl="")
            if args.timestamp:
                printb(bpfEntry"%-8.3f" % (time.time() - start_ts), nl="")
            if args.print_uid:
                printb(bpfEntry"%-6d" % event.uid, nl="")
            ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
            ppid = bpfEntry"%d" % ppid if ppid > 0 else bpfEntry"?"
            argv_text = bpfEntry' '.join(argv[event.pid]).replace(bpfEntry'\n', bpfEntry'\\n')
            printb(bpfEntry"%-16s %-7d %-7s %3d %s" % (event.comm, event.pid,
                                                ppid, event.retval, argv_text))
        try:
            del (argv[event.pid])
        except Exception:
            pass


# use this dict to store the corresponding function latency
# now we only consider 1 process
processInfo = {}


# usdt = USDT(pid=args.pid)
# usdt.enable_probe_or_bail("function__entry", "trace_entry")
# usdt.enable_probe_or_bail("function__return", "trace_return")

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
            if argv_v and argv_v[0] == bpfEntry'/usr/bin/python' and argv_v[1] == bpfEntry'test.py':
                usdt = USDT(pid=event.pid)
                usdt.enable_probe_or_bail("function__entry", "trace_entry")
                usdt.enable_probe_or_bail("function__return", "trace_return")
                bpf = BPF(src_file="ucall.c", usdt_contexts=[usdt])
                processInfo[event.pid] = {'usdt': usdt, 'bpf': bpf}

                print(f"captured python test.py process {event.pid}")

        # TODO   remove the accumulated argv if a process exit
        try:
            del (argv[event.pid])
        except Exception:
            pass


def get_data(bpf_pid):
    # Will be empty when no language was specified for tracing
    # bpf = bpfUsdtInfo[]
    data = list(map(lambda kv: (kv[0].clazz.decode('utf-8', 'replace') \
                                + "." + \
                                kv[0].method.decode('utf-8', 'replace'),
                                (kv[1].num_calls, kv[1].total_ns)),
                    bpf_pid["times"].items()))

    return sorted(data, key=lambda kv: kv[1][1])


def clear_terminal_line(end='\r'):
    columns, _ = get_terminal_size()
    print('', end='\r')  # return cursor to beginning
    print(' ' * (columns - 1), end=end)  # Fill line with spaces


# loop with callback to print_event
b["events"].open_perf_buffer(stat_event)

exit_signaled = False
while 1:
    try:
        b.perf_buffer_poll()
        # waiting for the script finished
        sleep(5)
    except KeyboardInterrupt:
        exit_signaled = True

    # print()
    for pid in processInfo:
        pidInfo = processInfo.get(pid, None)
        # todo remove here
        # clear_terminal_line()
        if pidInfo == None:
            continue

        bpf = pidInfo["bpf"]
        data = get_data(bpf)
        if len(data):
            print("%8s %-50s %8s %8s" % ("PID", "METHOD", "# CALLS", "TIME (ms)"))
            # print(f"{'PID':8} {'METHOD':-50} {'# CALLS':8} {'TIME (ms)':8}")
        # for key, value in data:
        for key, value in data:
            time = value[1] / 1000000.0
            print("%8d d%-50s %8d %6.2f" % (pid, key, value[0], time))
            if len(bpf["times"]) > 100:
                bpf["times"].clear()
        if exit_signaled:
            exit()
