// SPDX-License-Identifier: GPL-2.0
// Real eBPF Kernel Tracepoint Collector for Agent-Runtime-EDR
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define EVENT_EXECVE  1
#define EVENT_OPENAT  2

struct agent_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 event_type;
    char comm[TASK_COMM_LEN];
    char target[256];
};

BPF_PERF_OUTPUT(agent_events);
BPF_HASH(tracked_agent_pids, u32, u32);

static __always_inline int is_tracked(struct task_struct *task, u32 pid) {
    u32 *val = tracked_agent_pids.lookup(&pid);
    if (val) return 1;

    u32 ppid = task->real_parent->tgid;
    u32 *pval = tracked_agent_pids.lookup(&ppid);
    if (pval) {
        u32 one = 1;
        tracked_agent_pids.update(&pid, &one);
        return 1;
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!is_tracked(task, pid)) return 0;

    struct agent_event_t evt = {};
    evt.pid = pid;
    evt.ppid = task->real_parent->tgid;
    evt.uid = bpf_get_current_uid_gid();
    evt.event_type = EVENT_EXECVE;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.target, sizeof(evt.target), (void *)args->filename);
    agent_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!is_tracked(task, pid)) return 0;

    struct agent_event_t evt = {};
    evt.pid = pid;
    evt.ppid = task->real_parent->tgid;
    evt.uid = bpf_get_current_uid_gid();
    evt.event_type = EVENT_OPENAT;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.target, sizeof(evt.target), (void *)args->filename);
    agent_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
