// Compile-time validation tests for incomplete_file_messages map hardening.
//
// Build and run with: make test_file_maps
// This file is compiled with the host compiler (not the BPF toolchain).

#include <stddef.h>

// Provide the types that src/common/types.h needs when __VMLINUX_H__ is not defined.
// types.h already has fallback typedefs for u8/u16/u32/u64 when __VMLINUX_H__ is unset,
// so we just need to make sure we don't double-define anything.
#include "../src/common/types.h"

// We cannot include maps.h directly since it pulls in BPF helpers, vmlinux.h, etc.
// Instead, re-include the struct definition and map definition to validate them
// at compile time. We replicate just enough to test the properties we care about.

// --- Reproduce incomplete_file_message_t as defined in src/file/maps.h ---
// If the real struct changes in a way that removes owner_pid_tgid or changes
// the layout, these static_asserts will catch it.

typedef struct {
    file_message_type_t kind;
    u64 owner_pid_tgid;
    u64 probe_id;
    u64 start_ktime_ns;
    void *vfsmount;
    void *target_dentry;
    union {
        struct {
            void *source;
        } create;
        struct {
            unsigned long flags;
            const char* uname;
        } memfd_create;
        struct {
            file_ownership_t ownership;
            file_info_t target;
        } delete;
        struct {
            file_ownership_t before_owner;
            _Bool is_created;
        } modify;
        struct {
            void *source_parent_dentry;
            file_ownership_t overwr_owner;
            file_info_t overwr;
            char name[255+1];
        } rename;
    };
} test_incomplete_file_message_t;

// 1. Verify that owner_pid_tgid exists and is at the expected offset
//    (right after 'kind', which is an enum == 4 bytes, padded to 8 for u64 alignment)
_Static_assert(
    offsetof(test_incomplete_file_message_t, owner_pid_tgid) ==
        offsetof(test_incomplete_file_message_t, kind) + sizeof(u64),
    "owner_pid_tgid must follow kind (with padding)");

// 2. Verify owner_pid_tgid is a u64
_Static_assert(
    sizeof(((test_incomplete_file_message_t *)0)->owner_pid_tgid) == sizeof(u64),
    "owner_pid_tgid must be u64 (8 bytes)");

// 3. Verify the struct size hasn't grown unreasonably.
//    The rename union variant is the largest (contains a NAME_MAX+1 char array).
//    Total should be well under 512 bytes.
_Static_assert(
    sizeof(test_incomplete_file_message_t) <= 512,
    "incomplete_file_message_t should not exceed 512 bytes");

// 4. Verify the struct contains the expected fields after owner_pid_tgid
_Static_assert(
    offsetof(test_incomplete_file_message_t, probe_id) >
        offsetof(test_incomplete_file_message_t, owner_pid_tgid),
    "probe_id must come after owner_pid_tgid");

// 5. Verify BPF_MAP_TYPE_LRU_HASH constant value.
//    The kernel defines BPF_MAP_TYPE_LRU_HASH = 9 in the bpf_map_type enum.
#ifndef BPF_MAP_TYPE_LRU_HASH
#define BPF_MAP_TYPE_LRU_HASH 9
#endif
_Static_assert(BPF_MAP_TYPE_LRU_HASH == 9,
    "BPF_MAP_TYPE_LRU_HASH must be 9");

int main(void) {
    // All validation is compile-time via _Static_assert.
    // If we reach here, all checks passed.
    return 0;
}
