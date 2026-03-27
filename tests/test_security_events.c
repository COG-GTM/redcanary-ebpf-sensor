// SPDX-License-Identifier: GPL-2.0+
//
// Compile-time tests for security-events.c types and enum values.
// Build with: cc -Wall -Werror -I src -fsyntax-only tests/test_security_events.c
//        or:  cc -Wall -Werror -I src -o build/test_security_events tests/test_security_events.c

#include "common/types.h"
#include <stddef.h>

// Verify syscall pattern enum values exist and are distinct
_Static_assert(SP_MPROTECT != SP_IGNORE, "SP_MPROTECT must be defined and distinct from SP_IGNORE");
_Static_assert(SP_PKEY_MPROTECT != SP_IGNORE, "SP_PKEY_MPROTECT must be defined and distinct from SP_IGNORE");
_Static_assert(SP_MOUNT != SP_IGNORE, "SP_MOUNT must be defined and distinct from SP_IGNORE");
_Static_assert(SP_SETUID != SP_IGNORE, "SP_SETUID must be defined and distinct from SP_IGNORE");
_Static_assert(SP_SETGID != SP_IGNORE, "SP_SETGID must be defined and distinct from SP_IGNORE");
_Static_assert(SP_SETREUID != SP_IGNORE, "SP_SETREUID must be defined and distinct from SP_IGNORE");
_Static_assert(SP_SETREGID != SP_IGNORE, "SP_SETREGID must be defined and distinct from SP_IGNORE");
_Static_assert(SP_SETRESUID != SP_IGNORE, "SP_SETRESUID must be defined and distinct from SP_IGNORE");
_Static_assert(SP_SETRESGID != SP_IGNORE, "SP_SETRESGID must be defined and distinct from SP_IGNORE");

// Verify all pattern types are mutually distinct
_Static_assert(SP_MPROTECT != SP_PKEY_MPROTECT, "SP_MPROTECT and SP_PKEY_MPROTECT must be distinct");
_Static_assert(SP_MPROTECT != SP_MOUNT, "SP_MPROTECT and SP_MOUNT must be distinct");
_Static_assert(SP_MPROTECT != SP_SETUID, "SP_MPROTECT and SP_SETUID must be distinct");
_Static_assert(SP_MOUNT != SP_SETUID, "SP_MOUNT and SP_SETUID must be distinct");
_Static_assert(SP_SETUID != SP_SETGID, "SP_SETUID and SP_SETGID must be distinct");
_Static_assert(SP_SETREUID != SP_SETREGID, "SP_SETREUID and SP_SETREGID must be distinct");
_Static_assert(SP_SETRESUID != SP_SETRESGID, "SP_SETRESUID and SP_SETRESGID must be distinct");
_Static_assert(SP_SETUID != SP_SETREUID, "SP_SETUID and SP_SETREUID must be distinct");
_Static_assert(SP_SETGID != SP_SETREGID, "SP_SETGID and SP_SETREGID must be distinct");
_Static_assert(SP_SETRESUID != SP_SETREUID, "SP_SETRESUID and SP_SETREUID must be distinct");
_Static_assert(SP_SETRESGID != SP_SETREGID, "SP_SETRESGID and SP_SETREGID must be distinct");

// Verify trace_process_event_t struct layout
_Static_assert(sizeof(trace_process_event_t) > 0, "trace_process_event_t must have nonzero size");
_Static_assert(offsetof(trace_process_event_t, pid) == 0, "pid must be the first field");
_Static_assert(offsetof(trace_process_event_t, target_pid) > 0, "target_pid must exist after common fields");

// Verify write_process_memory_event_t struct layout
_Static_assert(sizeof(write_process_memory_event_t) > 0, "write_process_memory_event_t must have nonzero size");
_Static_assert(offsetof(write_process_memory_event_t, pid) == 0, "pid must be the first field");
_Static_assert(offsetof(write_process_memory_event_t, target_pid) > 0, "target_pid must exist after common fields");
_Static_assert(offsetof(write_process_memory_event_t, addresses) > offsetof(write_process_memory_event_t, target_pid),
               "addresses must come after target_pid");

// Verify write_process_memory_event_t is large enough to hold address data
_Static_assert(sizeof(((write_process_memory_event_t *)0)->addresses) == MAX_ADDRESSES * sizeof(u64),
               "addresses array must have MAX_ADDRESSES entries");

int main(void)
{
    return 0;
}
