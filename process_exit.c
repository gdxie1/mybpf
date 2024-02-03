    #include <linux/sched.h>

    struct data_t {
        u64 start_time;
        u64 exit_time;
        u32 pid;
        u32 tid;
        u32 ppid;
        int exit_code;
        u32 sig_info;
        char task[TASK_COMM_LEN];
    };

    BPF_QUEUE(exit_e, struct data_t, 10240);

   // BPF_PERF_OUTPUT(events);

    TRACEPOINT_PROBE(sched, sched_process_exit)
    {
        struct task_struct *task = (typeof(task))bpf_get_current_task();

        struct data_t data = {};

        data.start_time = task->start_time;
        data.exit_time = bpf_ktime_get_ns(),
        data.pid = task->tgid,
        data.tid = task->pid,
        data.ppid = task->real_parent->tgid,
        data.exit_code = task->exit_code >> 8,
        data.sig_info = task->exit_code & 0xFF,
        bpf_get_current_comm(&data.task, sizeof(data.task));

        exit_e.push(&data, BPF_EXIST);
        //events.perf_submit(args, &data, sizeof(data));
        return 0;
    }
