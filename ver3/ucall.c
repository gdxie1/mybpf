#include <linux/ptrace.h>

#define MAX_STRING_LENGTH 80

struct entry_t {
    u64 pid;
    u16 dir; //direction (0 entry, 1 return)
    char method[MAX_STRING_LENGTH];
    char clazz[MAX_STRING_LENGTH];
    u64 ts;
};

BPF_PERF_OUTPUT(calls)

//BPF_HASH(times, struct method_t, struct info_t);
//BPF_HASH(entry, struct entry_t, u64);              // timestamp at entry

//static inline bool prefix_method(char * actual){
//    char expected [] = "factorial";
//    for (int i = 0; i < sizeof(expected) - 1; ++i) {
//        if (expected[i] != actual[i]) {
//            return false;
//        }
//    }
//    return true;
//}

int trace_entry(struct pt_regs *ctx) {
    u64 method = 0, clazz = 0, zero = 0;

    struct entry_t data = {0};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns()

    bpf_usdt_readarg(1, ctx, &clazz);
    bpf_usdt_readarg(2, ctx, &method);

    bpf_probe_read_user(&data.clazz, sizeof(data.clazz),
                   (void *)method);
    bpf_probe_read_user(&data.method, sizeof(data.method),
                   (void *)method);

    data.dir = 0
    calls.perf_submit(ctx, data, sizeof(data));
    return 0;
}

int trace_return(struct pt_regs *ctx) {
    u64 method = 0, clazz = 0, zero = 0;

    struct entry_t data = {0};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns()

    bpf_usdt_readarg(1, ctx, &clazz);
    bpf_usdt_readarg(2, ctx, &method);

    bpf_probe_read_user(&data.clazz, sizeof(data.clazz),
                   (void *)method);
    bpf_probe_read_user(&data.method, sizeof(data.method),
                   (void *)method);

    data.dir = 1
    calls.perf_submit(ctx, data, sizeof(data));
    return 0;
}