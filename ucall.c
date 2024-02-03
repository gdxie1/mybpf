#include <linux/ptrace.h>

#define MAX_STRING_LENGTH 80

struct call_t {
    u64 pid;
    u64 depth;
    u16 dir; //direction of the calling. 0 for entry and 1 for exit
    u64 ts;
    char clazz[MAX_STRING_LENGTH];
    char method[MAX_STRING_LENGTH];
};

//BPF_HASH(times, struct method_t, struct info_t);
//BPF_HASH(entry, struct entry_t, u64);              // timestamp at entry
BPF_QUEUE(q_call, struct call_t, 1024);
BPF_HASH(entry, u64, u64);

static inline bool prefix_method(char * actual){
    char expected [] = "METHODNAME";
    for (int i = 0; i < sizeof(expected) - 1; ++i) {
        if (expected[i] != actual[i]) {
            return false;
        }
    }
    return true;
}

int trace_entry(struct pt_regs *ctx) {
    u64 clazz = 0, method = 0;
    u64 *depth, zero = 0;

    struct call_t data = {0};

    bpf_usdt_readarg(1, ctx, &clazz);    // filename really
    bpf_usdt_readarg(2, ctx, &method);


    bpf_probe_read_user(&data.clazz, sizeof(data.clazz),
                   (void *)clazz);
    bpf_probe_read_user(&data.method, sizeof(data.method),
                   (void *)method);

    //u64 timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.dir = 0;
    depth = entry.lookup_or_try_init(&data.pid, &zero);

    //we only trace one method and its following methods
    if (!depth) {
        depth = &zero;
    }
    if (!prefix_method(data.method) && (*depth == 0) ) { return 0; }

    data.depth = *depth + 1;
//     depth increase
    ++(*depth);
    q_call.push(&data, BPF_EXIST);
    return 0;
}

int trace_return(struct pt_regs *ctx) {
    u64 clazz = 0, method = 0;
    u64 *depth, zero = 0;

    struct call_t data = {0};

    bpf_usdt_readarg(1, ctx, &clazz);    // filename really
    bpf_usdt_readarg(2, ctx, &method);

    bpf_probe_read_user(&data.clazz, sizeof(data.clazz),
                   (void *)clazz);
    bpf_probe_read_user(&data.method, sizeof(data.method),
                   (void *)method);

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    depth = entry.lookup_or_try_init(&data.pid, &zero);
    //we only trace one method and its following methods

    if (!depth) {
        depth = &zero;
    }
    if (!prefix_method(data.method) && *depth == 0 ) { return 0; }

    data.depth = *depth;
    data.dir = 1;
//     depth increase
    if (*depth)
        --(*depth);

    q_call.push(&data, BPF_EXIST);

    return 0;
}