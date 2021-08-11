/**
 * Copyright (C) ARM Ltd. 2016-2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_IFUNC_H_
#define UCP_IFUNC_H_

#include <stddef.h>
#include <stdint.h>
#include <ucp/core/ucp_types.h>

/**
 * User-provided functions, must be present in the ifunc library source.
 */

/**
 * Launches the execution of the ifunc code. Invoked by the UCX runtime on the
 * target process when an ifunc message is received by ucp_poll_ifunc.
 *
 *      payload: a pointer to the delivered ifunc payload, which is populated by
 *               ifunc_payload_init_f on the source process.
 *
 *      payload_size: size of the payload in the received ifunc message.
 *
 *      target_args: points to user-provided arguments on the target process,
 *                   this is the same target_args pointer that was passed to the
 *                   ucp_poll_ifunc routine.
 */
typedef void (*ifunc_main_f)(void *payload,
                             size_t payload_size,
                             void *target_args);

/**
 * Calculates and returns the maximum size of the payload to send within an
 * ifunc message, for a given set of input arguments on the source process.
 * Invoked by the UCX runtime on the source process when an ifunc message is
 * being created by the ucp_ifunc_msg_create routine.
 *
 *      source_args: points to user-provided arguments on the source process,
 *                   this is the same source_args pointer that was passed to the
 *                   ucp_ifunc_msg_create routine.
 *
 *      source_args_size: size of the user-provided arguments, this is the same
 *                        source_args_size that was passed to the
 *                        ucp_ifunc_msg_create routine.
 *
 * N.B. This information can only be provided by the ifunc library itself, and
 * is needed by the UCX runtime to allocate a large enough ifunc message frame,
 * thus eliminating unnecessary memcpy's.
 */
typedef size_t (*ifunc_payload_get_max_size_f)(void *source_args,
                                               size_t source_args_size);

/**
 * Populate a payload buffer with the payload to send within an ifunc message,
 * for a given set of input arguments on the source process. Invoked by the UCX
 * runtime on the source process when an ifunc message is being created by the
 * ucp_ifunc_msg_create routine.
 *
 *      payload: points to the beginning of a allocated payload buffer allocated
 *               by the UCX runtime.
 *
 *      payload_size: size of the payload buffer, which is the maximum size
 *                    returned by a previous call to
 *                    ifunc_payload_get_max_size_f with the same source_args and
 *                    source_args_size.
 *
 *      source_args: points to user-provided arguments on the source process,
 *                   this is the same source_args pointer that was passed to the
 *                   ucp_ifunc_msg_create routine.
 *
 *      source_args_size: size of the user-provided arguments, this is the same
 *                        source_args_size that was passed to the
 *                        ucp_ifunc_msg_create routine.
 *
 * Returns 0 if succeed, other values stands for failure and instructs the
 * ucp_ifunc_msg_create call that invoked this routine to abort its operation
 * and free the message frame.
 *
 * N.B. The ucp_ifunc_msg_create routine calls ifunc_payload_get_max_size_f and
 * ifunc_payload_init_f with the same user-provided source_args and
 * source_args_size. The user is responsible for making sure the payload buffer
 * size returned by the first routine is indeed enough for the second routine to
 * fill.
 */
typedef int (*ifunc_payload_init_f)(void *payload,
                                    size_t payload_size,
                                    void *source_args,
                                    size_t source_args_size);

/**
 * Script generated functions & symbols
 */

/**
 * Loads page_address(_GLOBAL_OFFSET_TABLE_) into ifunc_name$got/ifunc_name_got
 * using the adrp instruction, and returns it.
 *
 * This function exists b/c we don't have a full implementation yet, the target
 * process can't assemble a GOT for a received ifunc with all the needed symbols
 * in the right place. So we use this hack to get the page address of the GOT of
 * the same ifunc library loaded on the target process when the target calls
 * ucp_ifunc_msg_create. When the target receives a ifunc message, the GOT page
 * address gets written to got_offset of the message frame by the
 * ucp_poll_ifunc routine, and the ifunc code will resolve all relocations
 * correctly.
 */
typedef void *(*ifunc_patch_got_f)();

/**
 * The script also generates and inserts:
 *
 *  void (*ifunc_name_preamble)()
 *      This function marks the beginning of the ifunc code to send with the
 *      ifunc message. It is invoked by ucp_poll_ifunc with the same argument
 *      list of ifunc_main_f. This function simply branches to the ifunc_main_f
 *      shipped with the message.
 *
 *  void* ifunc_name_got & void* ifunc_name$got
 *      This holds the 4KiB-aligned memory page address that contains the GOT of
 *      the ifunc library that is loaded by this process, it is located right
 *      behind ifunc_name_preamble so it also gets shipped with the ifunc
 *      message.
 *      The ifunc_patch_got_f routine modifies this variable and it can be
 *      located by got_offset in the ifunc message frame.
 *      The script replaces all GOT relocations with indirections through this
 *      pointer:
 *          Type 1: adrp xn, :got:symbol => ldr xn, ifunc$got
 *
 *          Type 2: ldr xn, :got:symbol => ldr xn, ifunc$got
 *                                         ldr xn, [xn, #:got_lo12:symbol]
 *
 *  symbol: ifunc_name_payload_start
 *      This symbol marks the end of the code and the rodata section, every byte
 *      between ifunc_name_preamble and this symbol gets shipped with the ifunc
 *      message.
 */

/**
 * Internal ifunc typedef's and data structures, not part of the contract with
 * the users.
 */

#define IFUNC_SIG_MAGIC 0x55

typedef uint32_t    ifunc_sz_t;
typedef uint16_t    ifunc_offset_t;
typedef uint8_t     ifunc_sig_t;

typedef struct ucp_ifunc {
    /* Handle to the ifunc dynamic lib loaded by dlopen */
    void *dlh;

    char name[UCP_IFUNC_NAME_MAX];

    /* Function pointers to the user-provided ifunc library functions */
    ifunc_main_f main;
    ifunc_payload_get_max_size_f payload_get_max_size;
    ifunc_payload_init_f payload_init;

    /* Point to the GOT page address pointer in the code section */
    void **code_got_loc;

    /* A copy of the ifunc library's GOT page address (ifunc_name_got) */
    void *got_page;

    /**
     * End of deliverable code section, start of the payload in delivered ifunc
     * Used to calculate code size
     */
    void *payload_start;

    /* Size of this ifunc's code & rodata, equals to payload_start - main */
    ifunc_sz_t code_size;
} ucp_ifunc_t;

typedef struct ifunc_hdr {
    /* Total length in bytes of this ifunc message frame (w/ trailer signal) */
    ifunc_sz_t frame_size;

    /* Offset in bytes from top of the header to the GOT page pointer */
    ifunc_offset_t got_offset;

    /* Offset in bytes from top of the header to start of the payload */
    ifunc_offset_t payload_offset;

    /**
     * IFUNCTODO: Only for the target process to query its local ifunc registry
     * and patch the message with the right GOT.
     */
    char name[UCP_IFUNC_NAME_MAX];

    /* Marks the end of the header and signals that the header is valid */
    ifunc_sig_t sig;
} ifunc_hdr_t;

#endif  /* UCP_IFUNC_H_ */
