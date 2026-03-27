// SPDX-License-Identifier: GPL-2.0+
#include "vmlinux.h"

#include "common/bpf_helpers.h"
#include "common/definitions.h"
#include "common/types.h"

#define PROT_EXEC 0x4

#define DECLARE_EVENT(TYPE, SP)                \
    u64 pid_tgid = bpf_get_current_pid_tgid(); \
    u32 pid = pid_tgid >> 32;                  \
    u32 tid = pid_tgid & 0xFFFFFFFF;           \
    u64 mono_ns = bpf_ktime_get_ns();          \
    TYPE ev = {                                \
        .syscall_pattern = SP,                 \
        .pid = pid,                            \
        .tid = tid,                            \
        .mono_ns = mono_ns,                    \
    }

/*
***** MAPS
*/
struct bpf_map_def SEC("maps/security_events") security_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/security_trace_events") security_trace_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0,
    .pinning = 0,
    .namespace = "",
};

/*
***** mprotect / pkey_mprotect
*/
SEC("kprobe/sys_mprotect")
int BPF_KPROBE_SYSCALL(sys_mprotect,
                       void *addr, u64 len, u64 prot)
{
    if (!(prot & PROT_EXEC))
    {
        goto Exit;
    }

    DECLARE_EVENT(write_process_memory_event_t, SP_MPROTECT);
    ev.target_pid = 0;
    ev.addresses[0] = (u64)addr;

    bpf_perf_event_output(ctx,
                          &security_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

Exit:
    return 0;
}

SEC("kprobe/sys_pkey_mprotect")
int BPF_KPROBE_SYSCALL(sys_pkey_mprotect,
                       void *addr, u64 len, u64 prot)
{
    if (!(prot & PROT_EXEC))
    {
        goto Exit;
    }

    DECLARE_EVENT(write_process_memory_event_t, SP_PKEY_MPROTECT);
    ev.target_pid = 0;
    ev.addresses[0] = (u64)addr;

    bpf_perf_event_output(ctx,
                          &security_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

Exit:
    return 0;
}

/*
***** mount
*/
SEC("kprobe/sys_mount")
int BPF_KPROBE_SYSCALL(sys_mount,
                       const char *source, const char *target,
                       const char *filesystemtype, u64 mountflags,
                       const void *data)
{
    DECLARE_EVENT(trace_process_event_t, SP_MOUNT);
    ev.target_pid = 0;

    bpf_perf_event_output(ctx,
                          &security_trace_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

    return 0;
}

/*
***** Privilege escalation: setuid/setgid family
*/
SEC("kprobe/sys_setuid")
int BPF_KPROBE_SYSCALL(sys_setuid, u32 uid)
{
    DECLARE_EVENT(trace_process_event_t, SP_SETUID);
    ev.target_pid = uid;

    bpf_perf_event_output(ctx,
                          &security_trace_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

    return 0;
}

SEC("kprobe/sys_setgid")
int BPF_KPROBE_SYSCALL(sys_setgid, u32 gid)
{
    DECLARE_EVENT(trace_process_event_t, SP_SETGID);
    ev.target_pid = gid;

    bpf_perf_event_output(ctx,
                          &security_trace_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

    return 0;
}

SEC("kprobe/sys_setreuid")
int BPF_KPROBE_SYSCALL(sys_setreuid, u32 ruid, u32 euid)
{
    DECLARE_EVENT(trace_process_event_t, SP_SETREUID);
    ev.target_pid = ruid;

    bpf_perf_event_output(ctx,
                          &security_trace_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

    return 0;
}

SEC("kprobe/sys_setregid")
int BPF_KPROBE_SYSCALL(sys_setregid, u32 rgid, u32 egid)
{
    DECLARE_EVENT(trace_process_event_t, SP_SETREGID);
    ev.target_pid = rgid;

    bpf_perf_event_output(ctx,
                          &security_trace_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

    return 0;
}

SEC("kprobe/sys_setresuid")
int BPF_KPROBE_SYSCALL(sys_setresuid, u32 ruid, u32 euid, u32 suid)
{
    DECLARE_EVENT(trace_process_event_t, SP_SETRESUID);
    ev.target_pid = ruid;

    bpf_perf_event_output(ctx,
                          &security_trace_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

    return 0;
}

SEC("kprobe/sys_setresgid")
int BPF_KPROBE_SYSCALL(sys_setresgid, u32 rgid, u32 egid, u32 sgid)
{
    DECLARE_EVENT(trace_process_event_t, SP_SETRESGID);
    ev.target_pid = rgid;

    bpf_perf_event_output(ctx,
                          &security_trace_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
