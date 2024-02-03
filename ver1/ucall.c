#include <linux/ptrace.h>

#define MAX_STRING_LENGTH 80

struct method_t {
    char clazz[MAX_STRING_LENGTH];
    char method[MAX_STRING_LENGTH];
    //char ret[MAX_STRING_LENGTH];
};
struct entry_t {
    u64 pid;
    u64 depth; //first bit is direction (0 entry, 1 return)
    struct method_t method;
};
struct info_t {
    u64 num_calls;
    u64 total_ns;
};

BPF_HASH(times, struct method_t, struct info_t);
BPF_HASH(entry, struct entry_t, u64);              // timestamp at entry

static inline bool prefix_method(char * actual){
    char expected [] = "factorial";
    for (int i = 0; i < sizeof(expected) - 1; ++i) {
        if (expected[i] != actual[i]) {
            return false;
        }
    }
    return true;
}

int trace_entry(struct pt_regs *ctx) {
   u64 clazz = 0, method = 0, val = 0;
   u64 *valp;
    struct entry_t data = {0};

    u64 timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();

    bpf_usdt_readarg(1, ctx, &clazz);    // filename really
    bpf_usdt_readarg(2, ctx, &method);

    bpf_probe_read_user(&data.method.clazz, sizeof(data.method.clazz),
                   (void *)clazz);
    bpf_probe_read_user(&data.method.method, sizeof(data.method.method),
                   (void *)method);

    //we only trace one method now
    if (!prefix_method(data.method.method)) { return 0; }

    entry.update(&data, &timestamp);

    return 0;
}

int trace_return(struct pt_regs *ctx) {
    u64 *entry_timestamp, clazz = 0, method = 0;

    struct info_t *info, zero = {};
    struct entry_t data = {};
    data.pid = bpf_get_current_pid_tgid();

    bpf_usdt_readarg(1, ctx, &clazz);    // filename really
    bpf_usdt_readarg(2, ctx, &method);

    bpf_probe_read_user(&data.method.clazz, sizeof(data.method.clazz),
                   (void *)clazz);
    bpf_probe_read_user(&data.method.method, sizeof(data.method.method),
                   (void *)method);
    //we only trace one method now
    if (!prefix_method(data.method.method)) { return 0; }

    entry_timestamp = entry.lookup(&data);

    if (!entry_timestamp) {
        return 0;   // missed the entry event
    }
    info = times.lookup_or_try_init(&data.method, &zero);
    if (info) {
        info->num_calls += 1;
        info->total_ns += bpf_ktime_get_ns() - *entry_timestamp;
    }
    entry.delete(&data);
    return 0;
}