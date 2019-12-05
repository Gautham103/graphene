#include "pal_linux.h"
#include "pal_security.h"
#include "pal_internal.h"
#include <api.h>

#include "ecall_types.h"

#define SGX_CAST(type, item) ((type)(item))

extern void * enclave_base, * enclave_top;

static struct atomic_int enclave_start_called = ATOMIC_INIT(0);

struct thread_map {
    unsigned int         tid;
    unsigned int         thread_index;
    unsigned int         status;
    sgx_arch_tcs_t*      tcs;
    unsigned long        tcs_addr;
    unsigned long        ssa_addr;
    unsigned long        tls_addr;
    unsigned long        enclave_entry;
};

void pal_thread_setup(void* ecall_args) {
    struct thread_map* thread_info = (struct thread_map* )ecall_args;
    unsigned long regular_flags = SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W |
                        SGX_SECINFO_FLAGS_REG | SGX_SECINFO_FLAGS_PENDING;
    SGX_DBG(DBG_I, "the created thread using tcs at  %p, tls at %p, ssa at %p\n",
			(void*)thread_info->tcs_addr, (void*)thread_info->tls_addr, (void*)thread_info->ssa_addr);

    sgx_accept_pages(regular_flags, thread_info->tcs_addr, thread_info->tcs_addr + PRESET_PAGESIZE, 0);
    sgx_accept_pages(regular_flags, thread_info->tls_addr, thread_info->tls_addr + PRESET_PAGESIZE, 0);
    sgx_accept_pages(regular_flags, thread_info->ssa_addr, thread_info->ssa_addr + 2 * PRESET_PAGESIZE, 0);

     // Setup TLS
    struct enclave_tls* tls = (struct enclave_tls*) thread_info->tls_addr;
    tls->enclave_size = GET_ENCLAVE_TLS(enclave_size);
    tls->tcs_offset = thread_info->tcs_addr;

    unsigned long stack_gap = thread_info->thread_index * (ENCLAVE_STACK_SIZE + PRESET_PAGESIZE); // There is a gap between stacks
    tls->initial_stack_offset = GET_ENCLAVE_TLS(initial_stack_offset) - stack_gap;

    tls->ssa = (void*)thread_info->ssa_addr;
    tls->gpr = tls->ssa + PRESET_PAGESIZE - sizeof(sgx_pal_gpr_t);

     // Setup TCS
    thread_info->tcs = (sgx_arch_tcs_t*) thread_info->tcs_addr;
    memset((void*)thread_info->tcs_addr, 0, PRESET_PAGESIZE);
    thread_info->tcs->ossa = thread_info->ssa_addr;
    thread_info->tcs->nssa = 2;
    thread_info->tcs->oentry = thread_info->enclave_entry;
    thread_info->tcs->ofs_base = 0;
    thread_info->tcs->ogs_base = thread_info->tls_addr;
    thread_info->tcs->ofs_limit = 0xfff;
    thread_info->tcs->ogs_limit = 0xfff;

     // PRE-ALLOCATE two pages for STACK
    unsigned long accept_flags = SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W |
                        SGX_SECINFO_FLAGS_REG | SGX_SECINFO_FLAGS_PENDING;

    sgx_accept_pages(accept_flags, tls->initial_stack_offset - 2 * PRESET_PAGESIZE, tls->initial_stack_offset, 0);
}

void pal_thread_create(void* ecall_args) {
    struct thread_map* thread_info = (struct thread_map*)ecall_args;
    unsigned long tcs_flags = SGX_SECINFO_FLAGS_TCS | SGX_SECINFO_FLAGS_MODIFIED;

    int rs = sgx_accept_pages(tcs_flags, thread_info->tcs_addr, thread_info->tcs_addr + PRESET_PAGESIZE, 0);
    if (rs != 0) SGX_DBG(DBG_E, "EACCEPT TCS Change failed: %d\n", rs);
}

/*
 * Called from enclave_entry.S to execute ecalls.
 *
 * During normal operation handle_ecall will not return. The exception is that
 * it will return if invalid parameters are passed. In this case
 * enclave_entry.S will go into an endless loop since a clean return to urts is
 * not easy in all cases.
 *
 * Parameters:
 *
 *  ecall_index:
 *      Number of requested ecall. Untrusted.
 *
 *  ecall_args:
 *      Pointer to arguments for requested ecall. Untrusted.
 *
 *  exit_target:
 *      Address to return to after EEXIT. Untrusted.
 *
 *  untrusted_stack:
 *      Address to urts stack. Restored before EEXIT and used for ocall
 *      arguments. Untrusted.
 *
 *  enclave_base_addr:
 *      Base address of enclave. Calculated dynamically in enclave_entry.S.
 *      Trusted.
 */
void handle_ecall (long ecall_index, void * ecall_args, void * exit_target,
                   void * untrusted_stack, void * enclave_base_addr)
{
    if (ecall_index < 0 || ecall_index >= ECALL_NR)
        return;

    if (!enclave_top) {
        enclave_base = enclave_base_addr;
        enclave_top = enclave_base_addr + GET_ENCLAVE_TLS(enclave_size);
    }

    SET_ENCLAVE_TLS(exit_target,     exit_target);
    SET_ENCLAVE_TLS(ustack_top,      untrusted_stack);
    SET_ENCLAVE_TLS(ustack,          untrusted_stack);
    SET_ENCLAVE_TLS(clear_child_tid, NULL);

    if (ecall_index == ECALL_THREAD_SETUP) {
        pal_thread_setup(ecall_args);

    } else if (ecall_index == ECALL_THREAD_CREATE) {
        pal_thread_create(ecall_args);

    } else if (atomic_cmpxchg(&enclave_start_called, 0, 1) == 0) {
        // ENCLAVE_START not yet called, so only valid ecall is ENCLAVE_START.
        if (ecall_index != ECALL_ENCLAVE_START) {
            // To keep things simple, we treat an invalid ecall_index like an
            // unsuccessful call to ENCLAVE_START.
            return;
        }

        ms_ecall_enclave_start_t * ms =
                (ms_ecall_enclave_start_t *) ecall_args;

        if (!ms || !sgx_is_completely_outside_enclave(ms, sizeof(*ms))) {
            return;
        }

        /* xsave size must be initialized early */
        init_xsave_size(ms->ms_sec_info->enclave_attributes.xfrm);

        /* pal_linux_main is responsible to check the passed arguments */
        pal_linux_main(ms->ms_args, ms->ms_args_size,
                       ms->ms_env, ms->ms_env_size,
                       ms->ms_sec_info);
    } else {
        // ENCLAVE_START already called (maybe successfully, maybe not), so
        // only valid ecall is THREAD_START.
        if (ecall_index != ECALL_THREAD_START) {
            return;
        }

        // Only allow THREAD_START after successful enclave initialization.
        if (!(pal_enclave_state.enclave_flags & PAL_ENCLAVE_INITIALIZED)) {
            return;
        }

        pal_start_thread();
    }
    // pal_linux_main and pal_start_thread should never return.
}
