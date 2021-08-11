/**
* Copyright (C) ARM Ltd. 2016-2021.  ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

/* Nearly-trivial ifunc for latency & throughput benchmarks. */
#include <stddef.h>


size_t b_payload_get_max_size(void *source_args, size_t source_args_size)
{
    (void)source_args;
    return source_args_size;
}


int b_payload_init(void *payload,
                   size_t payload_size,
                   void *source_args,
                   size_t source_args_size)
{
    (void)source_args;
    (void)source_args_size;
    (void)payload;
    (void)payload_size;
    return 0;
}


void b_main(void *payload, size_t payload_size, void *target_args)
{
    (void)payload;
    (void)payload_size;
    (void)target_args;
    *((size_t*)target_args) += 1;
}
