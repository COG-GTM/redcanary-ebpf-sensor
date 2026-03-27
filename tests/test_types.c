// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
//
// Compile-time and runtime checks for struct layout and CRC constant
// definitions.  Build with the host compiler:
//   cc -Wall -Werror -I src -o build/test_types tests/test_types.c
//

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "common/types.h"

// We only need the CRC constants (not the full vmlinux types), so
// provide the minimal typedef that offsets.h requires and then
// include it.
#ifndef __VMLINUX_H__
#define __VMLINUX_H__
// types already defined by types.h above
#endif
#include "common/offsets.h"

// --- helpers ----------------------------------------------------------------
#define STATIC_ASSERT(cond, msg) _Static_assert((cond), msg)

#define RUNTIME_ASSERT(cond, msg) do {            \
    if (!(cond)) {                                \
        fprintf(stderr, "FAIL: %s\n", (msg));     \
        failed = 1;                               \
    }                                             \
} while (0)

// --- syscall_info_t field existence & offset checks -------------------------
STATIC_ASSERT(
    sizeof(((syscall_info_t *)0)->pidns_inum) == sizeof(u32),
    "syscall_info_t.pidns_inum must be u32");

STATIC_ASSERT(
    sizeof(((syscall_info_t *)0)->mntns_inum) == sizeof(u32),
    "syscall_info_t.mntns_inum must be u32");

STATIC_ASSERT(
    offsetof(syscall_info_t, pidns_inum) > offsetof(syscall_info_t, mono_ns),
    "pidns_inum must come after mono_ns");

STATIC_ASSERT(
    offsetof(syscall_info_t, mntns_inum) > offsetof(syscall_info_t, pidns_inum),
    "mntns_inum must come after pidns_inum");

STATIC_ASSERT(
    offsetof(syscall_info_t, data) > offsetof(syscall_info_t, mntns_inum),
    "data must come after mntns_inum");

// Ensure no accidental padding blowup (original was ~112 bytes; adding
// two u32 fields should keep it well under 256).
STATIC_ASSERT(
    sizeof(syscall_info_t) <= 256,
    "syscall_info_t must not exceed 256 bytes");

// --- network_event_t field existence check ----------------------------------
STATIC_ASSERT(
    sizeof(((network_event_t *)0)->pidns_inum) == sizeof(u32),
    "network_event_t.pidns_inum must be u32");

STATIC_ASSERT(
    offsetof(network_event_t, pidns_inum) > offsetof(network_event_t, protos),
    "pidns_inum must come after protos in network_event_t");

STATIC_ASSERT(
    sizeof(network_event_t) <= 256,
    "network_event_t must not exceed 256 bytes");

// --- CRC constant runtime checks -------------------------------------------
int main(void) {
    int failed = 0;

    // Non-zero checks
    RUNTIME_ASSERT(CRC_TASK_STRUCT_NSPROXY != 0,
        "CRC_TASK_STRUCT_NSPROXY must be non-zero");
    RUNTIME_ASSERT(CRC_NSPROXY_PID_NS_FOR_CHILDREN != 0,
        "CRC_NSPROXY_PID_NS_FOR_CHILDREN must be non-zero");
    RUNTIME_ASSERT(CRC_NSPROXY_MNT_NS != 0,
        "CRC_NSPROXY_MNT_NS must be non-zero");
    RUNTIME_ASSERT(CRC_PID_NS_NS_INUM != 0,
        "CRC_PID_NS_NS_INUM must be non-zero");
    RUNTIME_ASSERT(CRC_MNT_NS_NS_INUM != 0,
        "CRC_MNT_NS_NS_INUM must be non-zero");

    // Uniqueness checks
    RUNTIME_ASSERT(CRC_TASK_STRUCT_NSPROXY != CRC_NSPROXY_PID_NS_FOR_CHILDREN,
        "namespace CRC constants must be unique (nsproxy vs pid_ns)");
    RUNTIME_ASSERT(CRC_TASK_STRUCT_NSPROXY != CRC_NSPROXY_MNT_NS,
        "namespace CRC constants must be unique (nsproxy vs mnt_ns)");
    RUNTIME_ASSERT(CRC_TASK_STRUCT_NSPROXY != CRC_PID_NS_NS_INUM,
        "namespace CRC constants must be unique (nsproxy vs pid_ns_inum)");
    RUNTIME_ASSERT(CRC_TASK_STRUCT_NSPROXY != CRC_MNT_NS_NS_INUM,
        "namespace CRC constants must be unique (nsproxy vs mnt_ns_inum)");
    RUNTIME_ASSERT(CRC_NSPROXY_PID_NS_FOR_CHILDREN != CRC_NSPROXY_MNT_NS,
        "namespace CRC constants must be unique (pid_ns vs mnt_ns)");
    RUNTIME_ASSERT(CRC_NSPROXY_PID_NS_FOR_CHILDREN != CRC_PID_NS_NS_INUM,
        "namespace CRC constants must be unique (pid_ns vs pid_ns_inum)");
    RUNTIME_ASSERT(CRC_NSPROXY_PID_NS_FOR_CHILDREN != CRC_MNT_NS_NS_INUM,
        "namespace CRC constants must be unique (pid_ns vs mnt_ns_inum)");
    RUNTIME_ASSERT(CRC_NSPROXY_MNT_NS != CRC_PID_NS_NS_INUM,
        "namespace CRC constants must be unique (mnt_ns vs pid_ns_inum)");
    RUNTIME_ASSERT(CRC_NSPROXY_MNT_NS != CRC_MNT_NS_NS_INUM,
        "namespace CRC constants must be unique (mnt_ns vs mnt_ns_inum)");
    RUNTIME_ASSERT(CRC_PID_NS_NS_INUM != CRC_MNT_NS_NS_INUM,
        "namespace CRC constants must be unique (pid_ns_inum vs mnt_ns_inum)");

    if (failed) {
        fprintf(stderr, "Some checks failed.\n");
        return 1;
    }

    printf("All checks passed.\n");
    return 0;
}
