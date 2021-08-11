/**
* Copyright (C) ARM Ltd. 2016-2021.  ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

/* Hello ifunc world, simple smoke test. */
#include <stdio.h>
#include <stdint.h>

#define MIN(a,b) (a < b) ? a : b

/* Make sure global variables also get shipped in the ifunc. */
size_t global_var = 42;

/* Make sure other user-defined functions also get shipped in the ifunc. */
uint64_t fib(uint64_t n)
{
    if (n < 2) {
        return 1;
    } else {
        return fib(n - 1) + fib(n - 2);
    }
}

size_t hello_payload_get_max_size(void *source_args, size_t source_args_size)
{
    (void)source_args;
    (void)source_args_size;
    return fib(17) + global_var;
}

int hello_payload_init(void *payload,
                     size_t payload_size,
                     void *source_args,
                     size_t source_args_size)
{
    size_t len = MIN(source_args_size, payload_size);

    for (size_t i = 0; i < len; i++) {
        ((uint8_t*)payload)[i] = ((uint8_t*)source_args)[i];
    }

    return 0;
}

void hello_main(void *payload, size_t payload_size, void *target_args)
{
    printf("Hello: payload %p, payload_size %lu, target_args %p\n",
           payload, payload_size, target_args);
    /* Verify that everything works. */
    printf("payload_size: fib(17) + 42 = %lu\n", fib(17) + global_var);
}
