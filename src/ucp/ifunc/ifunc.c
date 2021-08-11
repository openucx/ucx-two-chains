/**
 * Copyright (C) ARM Ltd. 2016-2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "ifunc.h"

#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>

#include <ucs/sys/sys.h>
#include <ucs/arch/cpu.h>
#include <ucs/debug/log.h>
#include <ucs/debug/assert.h>
#include <ucs/config/parser.h>
#include <ucs/datastruct/khash.h>

#include <ucp/api/ucp.h>
#include <ucp/core/ucp_context.h>

static inline void*
ifunc_pull_symbol(void *dlh, const char *fmt, const char *ifunc_name)
{
    void *rsym;
    char symbol_name[UCP_IFUNC_SYMBOL_MAX];
    snprintf(symbol_name, UCP_IFUNC_SYMBOL_MAX, fmt, ifunc_name);
    rsym = dlsym(dlh, symbol_name);
    ucs_info("IFUNC pulled symbol %s @ %p, err = %s\n", symbol_name, rsym,
             dlerror());
    return rsym;
}

/**
 * Register an ifunc by loading the dynamic library identified by the ifunc's
 * name.
 */
ucs_status_t ucp_register_ifunc(ucp_context_h context,
                                const char *ifunc_name,
                                ucp_ifunc_h *ifunc_p)
{
    ucs_status_t status;
    ucp_ifunc_h ih;
    char ifunc_lib_path[UCP_IFUNC_FILE_NAME_MAX];
    ifunc_patch_got_f patch_got;
    uint64_t pg_sz, code_sz, code_pg_sz;
    void *main_pg;
    khint_t map_iter;
    int ret, idx;

    /* Check if this ifunc is in registered state */
    map_iter = kh_get(ifunc_map_t, context->ifuncs_map, ifunc_name);
    if (map_iter != kh_end(context->ifuncs_map)) {
        ucs_warn("IFUNC double registration of ifunc %s\n", ifunc_name);
        idx = kh_val(context->ifuncs_map, map_iter);
        *ifunc_p = context->ifuncs[idx];
        return UCS_OK;
    }

    *ifunc_p = NULL;

    ih = calloc(1, sizeof(*ih));

    snprintf(ifunc_lib_path, UCP_IFUNC_FILE_NAME_MAX, "%s/%s.so",
             context->ifunc_lib_dir, ifunc_name);

    if (dlopen(ifunc_lib_path, RTLD_NOW | RTLD_NOLOAD) == NULL) {
        ih->dlh = dlopen(ifunc_lib_path, RTLD_NOW | RTLD_GLOBAL);
        if (ih->dlh == NULL) {
            ucs_warn("IFUNC dlopen of [%s] failed with error %s\n",
                     ifunc_lib_path, dlerror());
            status = UCS_ERR_IO_ERROR;
            goto err;
        }
        ucs_info("IFUNC lib [%s] loaded successfully\n", ifunc_lib_path);
    } else {
        /* IFUNCTODO: Do we allow double-registration? */
        ucs_info("IFUNC lib [%s] already loaded\n", ifunc_lib_path);
    }

    strncpy(ih->name, ifunc_name, UCP_IFUNC_NAME_MAX - 1);
    ih->name[UCP_IFUNC_NAME_MAX - 1] = 0;

    ih->main = ifunc_pull_symbol(ih->dlh, "%s_preamble", ifunc_name);
    ucs_assert(ih->main != NULL);

    ih->payload_get_max_size = ifunc_pull_symbol(ih->dlh,
                                                 "%s_payload_get_max_size",
                                                 ifunc_name);
    ucs_assert(ih->payload_get_max_size != NULL);

    ih->payload_init = ifunc_pull_symbol(ih->dlh, "%s_payload_init",
                                         ifunc_name);
    ucs_assert(ih->payload_init != NULL);

    ih->code_got_loc = ifunc_pull_symbol(ih->dlh, "%s_got", ifunc_name);
    ucs_assert(ih->code_got_loc != NULL);
    ucs_assert((char*)ih->code_got_loc > (char*)ih->main);

    ih->payload_start = ifunc_pull_symbol(ih->dlh, "%s_payload_start",
                                          ifunc_name);
    ucs_assert(ih->payload_start != NULL);
    ucs_assert((char*)ih->payload_start > (char*)ih->code_got_loc);
    ih->code_size = (char*)ih->payload_start - (char*)ih->main;

    patch_got = ifunc_pull_symbol(ih->dlh, "%s_patch_got", ifunc_name);
    ucs_assert(patch_got != NULL);

    ucs_info("IFUNC %s, code size %d\n", ifunc_name, ih->code_size);

    /* Make lib writeable to set GOT patch */
    pg_sz = sysconf(_SC_PAGESIZE);
    main_pg = (void*)(((uint64_t)ih->main / pg_sz) * pg_sz);
    code_sz = ((char*)ih->payload_start - (char*)ih->main);
    code_pg_sz = (code_sz % pg_sz == 0) ? code_sz
                                        : ((code_sz / pg_sz) + 1) * pg_sz;
    ret = mprotect(main_pg, code_pg_sz, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (ret != 0) {
        ucs_warn("IFUNC failed to set rwx privilege on GOT ptr memory: %s\n",
                  strerror(errno));
        status = UCS_ERR_IO_ERROR;
        goto err;
    }

    /* IFUNCTODO: In the full implementation we don't need got_page. */
    ih->got_page = patch_got();
    ucs_assert(ih->got_page != NULL);
    ucs_assert(ih->got_page == *(ih->code_got_loc));

    ret = mprotect(main_pg, code_pg_sz, PROT_READ | PROT_EXEC);
    if (ret != 0) {
        ucs_warn("IFUNC failed to set rx privilege on GOT ptr memory: %s\n",
                  strerror(errno));
    }

    /**
     * Handler creation done, update the registry and hash table.
     *
     * Warning: khash stores the address of the string key only, but it also
     *          uses the hash of the string to do internal calculations. Using
     *          the same address to refer to a different string key leads to
     *          strange behaviors, don't use ifunc_name here! Use a copy.
     */
    map_iter = kh_put(ifunc_map_t, context->ifuncs_map, ih->name, &ret);
    assert(ret != -1);
    for (idx = 0; idx < UCP_REG_IFUNC_MAX; idx++) {
        if (context->ifuncs[idx] == NULL) {
            context->ifuncs[idx] = ih;
            *ifunc_p = ih;
            kh_val(context->ifuncs_map, map_iter) = idx;
            return UCS_OK;
        }
    }

    status = UCS_ERR_EXCEEDS_LIMIT;
    ucs_warn("IFUNC ifunc registry is full, unable to register ifunc %s\n",
             ifunc_name);

err:
    ucs_free(ih);
    return status;
}

void ucp_deregister_ifunc(ucp_context_h context, ucp_ifunc_h ifunc_h)
{
    khint_t map_iter;

    if (ifunc_h == NULL) {
        ucs_warn("IFUNC deregistering NULL ifunc handler\n");
        return;
    }

    /**
     * IFUNCTODO: double deregistration could cause use-after-free when
     * accessing ifunc_h->name, how to plug this hole?
     */
    map_iter = kh_get(ifunc_map_t, context->ifuncs_map, ifunc_h->name);
    if (map_iter == kh_end(context->ifuncs_map)) {
        ucs_warn("IFUNC double ifunc deregistration\n");
        return;
    }

    ucs_info("IFUNC deregistering ifunc %s\n", ifunc_h->name);
    context->ifuncs[kh_val(context->ifuncs_map, map_iter)] = NULL;
    kh_del(ifunc_map_t, context->ifuncs_map, map_iter);

    ucs_assert(ifunc_h->dlh != NULL);
    dlclose(ifunc_h->dlh);
    free(ifunc_h);
}

ucs_status_t ucp_ifunc_msg_create(ucp_ifunc_h ifunc_h,
                                  void *source_args,
                                  size_t source_args_size,
                                  ucp_ifunc_msg_t* msg_p)
{
    size_t payload_size, frame_size;
    ifunc_hdr_t *hdr;
    char *frame, *payload;
    int ret;

    ucs_assert(ifunc_h != NULL);
    ucs_assert(msg_p != NULL);

    payload_size = ifunc_h->payload_get_max_size(source_args, source_args_size);

    frame_size = sizeof(ifunc_hdr_t) + ifunc_h->code_size + payload_size +
                 sizeof(ifunc_sig_t);

    /* Touches and clears the message frame memory. */
    frame = calloc(frame_size, 1);
    payload = frame + sizeof(ifunc_hdr_t) + ifunc_h->code_size;

    hdr = (ifunc_hdr_t*)frame;

    hdr->frame_size = frame_size;
    hdr->got_offset = (char*)ifunc_h->code_got_loc - (char*)ifunc_h->main +
                      sizeof(ifunc_hdr_t);
    hdr->payload_offset = (char*)ifunc_h->payload_start - (char*)ifunc_h->main +
                          sizeof(ifunc_hdr_t);
    strncpy(hdr->name, ifunc_h->name, UCP_IFUNC_NAME_MAX);
    hdr->sig = IFUNC_SIG_MAGIC;

    ucs_info("IFUNC payload size %ld, frame size %ld\n",
             payload_size, frame_size);

    memcpy(frame + sizeof(ifunc_hdr_t), ifunc_h->main, ifunc_h->code_size);

    ret = ifunc_h->payload_init(payload, payload_size, source_args,
                                source_args_size);

    if (ret != 0) {
        ucs_warn("IFUNC payload_init failed with %d\n", ret);
        free(frame);
        return UCS_ERR_CANCELED;
    }

    msg_p->ifunc_h = ifunc_h;
    msg_p->frame = frame;
    msg_p->frame_size = frame_size;

    *((ifunc_sig_t*)(frame + frame_size - 1)) = IFUNC_SIG_MAGIC;

    return UCS_OK;
}

void ucp_ifunc_msg_free(ucp_ifunc_msg_t msg)
{
    msg.ifunc_h = NULL;
    msg.frame_size = 0;
    free(msg.frame);
}

/**
 * For now this function is very simple, but it could get complicated when we
 * switch to send-recv and/or implement optimizations like avoid sending
 * duplicated code sections.
 */
ucs_status_t ucp_ifunc_send_nbix(ucp_ep_h ep,
                                 ucp_ifunc_msg_t msg,
                                 uint64_t remote_addr,
                                 ucp_rkey_h rkey)
{
    ucs_status_t status;

    status = ucp_put_nbi(ep, msg.frame, msg.frame_size, remote_addr, rkey);

    return status;
}

static inline int
arch_safe_cmp_wait_u8(volatile uint8_t *ptr, uint8_t val)
{
#ifdef __ARM_ARCH
    /* IFUNCTODO: Better than the WFE impl in ucs? */
    uint8_t tmp = 0;
    asm volatile("ldaxrb %w0, [%1]\n"
                 "cmp %w2, %w0, uxtb\n"
                 "b.eq 1f\n"
                 "wfe\n"
                 "1:\n"
                 : "=&r"(tmp)
                 : "r"(ptr),
                   "r"(val)
                 : "memory");
    return (tmp != val);
#else
    ucs_arch_wait_mem((uint8_t*)ptr);
    return (*ptr != val);
#endif /* __ARM_ARCH */
}

void flush_cb(void* request, ucs_status_t status)
{
    (void)request;
    (void)status;
}

ucs_status_t ucp_poll_ifunc(ucp_context_h context,
                            void *buffer,
                            size_t buffer_size,
                            void *target_args)
{
    ifunc_hdr_t *hdr;
    ifunc_sig_t *hdr_sig;
    ifunc_sig_t *trailer_sig;
    khint_t map_iter;
    ucp_ifunc_h ifunc_h;
    void **got_page;
    ifunc_main_f mainf;
    void* payload;
    size_t payload_size;
    ucs_status_t status;

    hdr = buffer;
    hdr_sig = &(hdr->sig);

    if (*hdr_sig != IFUNC_SIG_MAGIC) {
        status = UCS_ERR_NO_MESSAGE;
        goto err;
    }

    /*
     * IFUNCTODO:
     * Tests show that for normal CPUs, either fence(dmb) or isb is enough.
     * Cache clear is super-expensive but required on Neoverse-N1.
     */
    ucs_clear_cache((void*)((char*)buffer + sizeof(ifunc_hdr_t)),
                    (void*)((char*)buffer + hdr->payload_offset));
    /* ucs_memory_cpu_fence(); */
    /* ucs_aarch64_isb(); */

    /* IFUNCTODO: buffer_size is used here only */
    if (ucs_unlikely(buffer_size < hdr->frame_size)) {
        ucs_warn("IFUNC ifunc %s rejected, message too long: %d > %lu\n",
                 hdr->name, hdr->frame_size, buffer_size);
        status = UCS_ERR_CANCELED;
        goto err_invalidate_header;
    }

    trailer_sig = buffer + hdr->frame_size - 1;
    if (*trailer_sig != IFUNC_SIG_MAGIC) {
        /* IFUNCTODO: this happens frequent enough, wait or goto err? */
        ucs_info("IFUNC waiting on trailer signal of ifunc %s\n", hdr->name);
        while (arch_safe_cmp_wait_u8(trailer_sig, IFUNC_SIG_MAGIC)) {};
    }

    map_iter = kh_get(ifunc_map_t, context->ifuncs_map, hdr->name);
    if (ucs_unlikely(map_iter == kh_end(context->ifuncs_map))) {
        ucs_info("IFUNC received unknown ifunc %s\n", hdr->name);

        if (ucp_register_ifunc(context, hdr->name, &ifunc_h) != UCS_OK) {
            ucs_warn("IFUNC failed to auto-register unknown ifunc %s\n",
                      hdr->name);
            status = UCS_ERR_CANCELED;
            goto err_invalidate_buffer;
        }
    } else {
        ifunc_h = context->ifuncs[kh_val(context->ifuncs_map, map_iter)];
    }

    /**
     * IFUNCTODO: try borrow this image's GOT?
     * asm volatile ("adrp %0, :got:_GLOBAL_OFFSET_TABLE_" : "=r" (got_page));
     */
    got_page = (void**)((char*)buffer + hdr->got_offset);
    ucs_info("IFUNC patching ifunc %s message GOT page from %p to %p\n",
             hdr->name, *got_page, ifunc_h->got_page);
    *got_page = ifunc_h->got_page;

    mainf = (ifunc_main_f)(buffer + sizeof(ifunc_hdr_t));
    payload = buffer + hdr->payload_offset;
    payload_size = hdr->frame_size - hdr->payload_offset - sizeof(ifunc_sig_t);
    mainf(payload, payload_size, target_args);

    status = UCS_OK;

err_invalidate_buffer:
    *trailer_sig = 0;

err_invalidate_header:
    *hdr_sig = 0;

err:
    return status;
}
