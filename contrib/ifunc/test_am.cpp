/**
* Copyright (C) ARM Ltd. 2016-2021.  ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

// Minimal UCP application to test UCP AM
// Single pair of workers & endpoints, no heap & rkeys
// IFUNCTODO: Use UCP_AM_SEND_FLAG_EAGER for all payload sizes?
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <ctime>
#include <unistd.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ctime>
#include <iomanip>

#include <ucp/api/ucp.h>


#define PORT 13337
#define HEAP_SIZE_LOG 31    // For benchmark iteration calculation only

int conn_skt;

ucp_context_h ucp_ctx;
ucp_worker_h wrkr;
ucp_ep_h ep;

ucp_address_t* wrkr_addr;
ucp_address_t* wrkr_rmt_addr;
size_t wrkr_addr_sz, wrkr_rmt_addr_sz;


struct ucx_request {
    uint64_t completed;
};


void request_init(void* request)
{
    auto r = (ucx_request*) request;
    r->completed = 0;
}


void request_cleanup(void* request)
{
    auto r       = static_cast<ucx_request*>(request);
    r->completed = 1;
}


void flush_callback(void *request, ucs_status_t status)
{
    (void)request;
    (void)status;
}


ucs_status_t flush(bool flush_worker)
{
    void* request;
    if (flush_worker) {
        request = ucp_worker_flush_nb(wrkr, 0, flush_callback);
    } else {
        request = ucp_ep_flush_nb(ep, 0, flush_callback);
    }
    if (request == NULL) {
        return UCS_OK;
    } else if (UCS_PTR_IS_ERR(request)) {
        return UCS_PTR_STATUS(request);
    } else {
        ucs_status_t status;
        do {
            ucp_worker_progress(wrkr);
            status = ucp_request_check_status(request);
        } while (status == UCS_INPROGRESS);
        ucp_request_free(request);
        return status;
    }
}


void socket_p2p_sync()
{
    ssize_t status;
    const int8_t send_var = 42;
    int8_t recv_var       = 0;

    status = send(conn_skt, static_cast<const void*>(&send_var), sizeof(send_var), 0);
    assert(status == sizeof(send_var));

    status = recv(conn_skt, static_cast<void*>(&recv_var), sizeof(recv_var), 0);
    assert(status == sizeof(send_var));

    assert(recv_var == 42);
}


ucs_status_t am_benchmark_cb(void* arg, void* data, size_t length,
                             ucp_ep_h reply_ep, unsigned flags)
{
    (void)data;
    (void)length;
    (void)reply_ep;
    (void)flags;
    *((size_t*)arg) += 1;
    return UCS_OK;
}


void am_send_cb(void* req, ucs_status_t status)
{
    (void)status;
    (void)req;
}


void request_wait(ucs_status_ptr_t sp)
{
    if (sp == NULL) {
        /* Sent immediately */
    } else if (UCS_PTR_IS_ERR(sp)) {
        ucp_request_cancel(wrkr, sp);
        std::cout << ucs_status_string(UCS_PTR_STATUS(sp)) << '\n';
    } else {
        ucs_status_t s;

        do {
            ucp_worker_progress(wrkr);
            s = ucp_request_check_status(sp);
        } while (s == UCS_INPROGRESS);

        ucp_request_free(sp);
    }
}


void run_server()
{
    size_t counter = 0;
    ucs_status_t s;

    s = ucp_worker_set_am_handler(wrkr, 0, am_benchmark_cb, &counter, 0);
    assert(s == UCS_OK);

    socket_p2p_sync();

    std::cout << "\nBegin throughput benchmark\n";

    timespec t0, t1;

    for (int pl_sz_log = 0; pl_sz_log <= 20; pl_sz_log++) {
        const size_t slot_sz_log = std::max(10, pl_sz_log + 1);
        const size_t n_slots = 1UL << (HEAP_SIZE_LOG - 1 - slot_sz_log);
        const size_t n_iters = std::max((size_t)50000, n_slots * 4);
        const size_t n_warmup = n_iters / 10;

        counter = 0;

        socket_p2p_sync();

        for (size_t i = 0; i < n_iters + n_warmup; i++) {
            if (i == n_warmup) {
                clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
            }

            do {
                ucp_worker_progress(wrkr);
            } while (i == counter);
        }

        clock_gettime(CLOCK_MONOTONIC_RAW, &t1);

        assert(counter == n_iters + n_warmup);

        const double T = (t1.tv_sec - t0.tv_sec) +
                         (t1.tv_nsec - t0.tv_nsec) / 1e9;

        std::cout << std::setw(7) << (1UL << pl_sz_log) << ": "
                  << std::scientific << std::setprecision(3)
                  << (n_iters / T) << " messages/s\n";
    }

    socket_p2p_sync();

    std::cout << "\nBegin ping-pong benchmark\n";

    for (int pl_sz_log = 0; pl_sz_log <= 20; pl_sz_log++) {
        const size_t n_iters = pl_sz_log > 16 ? 20000 : 1000000;
        const size_t n_warmup = n_iters / 10;

        counter = 0;

        void* payload = calloc(1UL << pl_sz_log, 1);

        socket_p2p_sync();

        for (size_t i = 0; i < n_iters + n_warmup; i++) {
            if (i == n_warmup) {
                clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
            }

            do {
                ucp_worker_progress(wrkr);
            } while (i == counter);

            ucs_status_ptr_t sp;

            sp = ucp_am_send_nb(ep, 0, payload, 1UL << pl_sz_log,
                                ucp_dt_make_contig(1), am_send_cb, 0);
            request_wait(sp);
        }

        clock_gettime(CLOCK_MONOTONIC_RAW, &t1);

        assert(counter == n_iters + n_warmup);

        const double T = (t1.tv_sec - t0.tv_sec) * 1e6 +
                         (t1.tv_nsec - t0.tv_nsec) / 1e3;

        std::cout << std::setw(7) << (1UL << pl_sz_log) << ": "
                  << std::scientific << std::setprecision(3)
                  << (T / n_iters) << " us\n";

        free(payload);
    }
}


void run_client()
{
    socket_p2p_sync();

    std::cout << "\nBegin throughput benchmark\n";

    timespec t0, t1;

    // Payload size: 1B to 1MB
    for (int pl_sz_log = 0; pl_sz_log <= 20; pl_sz_log++) {
        // Min slot size 1KiB, otherwise payload * 2 to hold hdr & code & sig
        const size_t slot_sz_log = std::max(10, pl_sz_log + 1);
        // Only use the 1st half of the heap
        const size_t n_slots = 1UL << (HEAP_SIZE_LOG - 1 - slot_sz_log);

        const size_t n_iters = std::max((size_t)50000, n_slots * 4);
        const size_t n_warmup = n_iters / 10;

        void* payload = calloc(1UL << pl_sz_log, 1);

        socket_p2p_sync();

        for (size_t i = 0; i < n_iters + n_warmup; i++) {
            if (i == n_warmup) {
                clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
            }

            ucs_status_ptr_t sp;

            sp = ucp_am_send_nb(ep, 0, payload, 1UL << pl_sz_log,
                                ucp_dt_make_contig(1), am_send_cb, 0);
            request_wait(sp);
        }

        flush(false);
        clock_gettime(CLOCK_MONOTONIC_RAW, &t1);

        const double T = (t1.tv_sec - t0.tv_sec) +
                         (t1.tv_nsec - t0.tv_nsec) / 1e9;

        std::cout << std::setw(7) << (1UL << pl_sz_log) << ": "
                  << std::scientific << std::setprecision(3)
                  << (n_iters / T) << " messages/s\n";

        free(payload);
    }

    socket_p2p_sync();

    std::cout << "\nBegin ping-pong benchmark\n";

    size_t counter = 0;
    ucs_status_t s;

    s = ucp_worker_set_am_handler(wrkr, 0, am_benchmark_cb, &counter, 0);
    assert(s == UCS_OK);

    for (int pl_sz_log = 0; pl_sz_log <= 20; pl_sz_log++) {
        // Min slot size 1KiB, otherwise payload * 2 to hold hdr & code & sig
        const size_t n_iters = pl_sz_log > 16 ? 20000 : 1000000;
        const size_t n_warmup = n_iters / 10;

        counter = 0;

        void* payload = calloc(1UL << pl_sz_log, 1);

        socket_p2p_sync();

        for (size_t i = 0; i < n_iters + n_warmup; i++) {
            if (i == n_warmup) {
                clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
            }

            ucs_status_ptr_t sp;

            sp = ucp_am_send_nb(ep, 0, payload, 1UL << pl_sz_log,
                                ucp_dt_make_contig(1), am_send_cb, 0);
            request_wait(sp);

            do {
                ucp_worker_progress(wrkr);
            } while (i == counter);
        }

        clock_gettime(CLOCK_MONOTONIC_RAW, &t1);

        assert(counter == n_iters + n_warmup);

        const double T = (t1.tv_sec - t0.tv_sec) * 1e6 +
                         (t1.tv_nsec - t0.tv_nsec) / 1e3;

        std::cout << std::setw(7) << (1UL << pl_sz_log) << ": "
                  << std::scientific << std::setprecision(3)
                  << (T / n_iters) << " us\n";

        free(payload);
    }
}


int server_connect()
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    int optval = 1;

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEADDR, &optval, sizeof(optval));

    sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

    int ret = bind(server_fd, (sockaddr*)&addr, sizeof(addr));
    assert(ret == 0);

    listen(server_fd, 0);

    std::cout << "\nServer waiting for connection...\n\n";

    int connected_fd = accept(server_fd, NULL, NULL);

    close(server_fd);

    return connected_fd;
}


int client_connect(const char* server_name)
{
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);

    hostent* he = gethostbyname(server_name);

    sockaddr_in addr;

    addr.sin_port = htons(PORT);
    addr.sin_family = he->h_addrtype;

    memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

    memcpy(&(addr.sin_addr), he->h_addr_list[0], he->h_length);

    int ret = connect(client_fd, (sockaddr*)&addr, sizeof(addr));
    assert(ret == 0);

    return client_fd;
}


void exchange_worker_addr()
{
    ssize_t nbytes;

    nbytes = send(conn_skt, &wrkr_addr_sz, sizeof(wrkr_addr_sz), 0);
    assert(nbytes == sizeof(wrkr_addr_sz));

    nbytes = send(conn_skt, wrkr_addr, wrkr_addr_sz, 0);
    assert(nbytes == static_cast<ssize_t>(wrkr_addr_sz));

    nbytes = recv(conn_skt, &wrkr_rmt_addr_sz, sizeof(wrkr_rmt_addr_sz), 0);
    assert(nbytes == sizeof(wrkr_rmt_addr_sz));

    wrkr_rmt_addr = (ucp_address_t*)malloc(wrkr_rmt_addr_sz);

    nbytes = recv(conn_skt, wrkr_rmt_addr, wrkr_rmt_addr_sz, 0);
    assert(nbytes == static_cast<ssize_t>(wrkr_rmt_addr_sz));

    std::cout << "Local worker address " << wrkr_addr_sz
              << " bytes, remote worker address " << wrkr_rmt_addr_sz
              << " bytes\n";
}


void prepare_ep_rkey()
{
    ucs_status_t s;
    ucp_ep_params_t ep_params;

    ep_params.field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS;
    ep_params.address = wrkr_rmt_addr;

    s = ucp_ep_create(wrkr, &ep_params, &ep);
    assert(s == UCS_OK);
}


int main(int argc, char** argv)
{
    ucp_config_t* env_cfg;
    ucp_config_read(NULL, NULL, &env_cfg);
    // ucp_config_print(env_cfg, stdout, "UCX environment variables", UCS_CONFIG_PRINT_HEADER);
    // ucp_config_print(env_cfg, stdout, NULL, UCS_CONFIG_PRINT_CONFIG);

    ucp_params_t params;

    params.field_mask = UCP_PARAM_FIELD_FEATURES     |
                        UCP_PARAM_FIELD_REQUEST_INIT |
                        UCP_PARAM_FIELD_REQUEST_SIZE |
                        UCP_PARAM_FIELD_REQUEST_CLEANUP;

    params.features = UCP_FEATURE_AM | UCP_FEATURE_WAKEUP;

    params.request_size = sizeof(ucx_request);
    params.request_init = request_init;
    params.request_cleanup = request_cleanup;

    ucp_init(&params, env_cfg, &ucp_ctx);

    ucp_config_release(env_cfg);

    // ucp_context_print_info(ucp_ctx, stdout);


    // Setup a worker
    ucp_worker_params_t wrkr_params;

    wrkr_params.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    wrkr_params.thread_mode = UCS_THREAD_MODE_SINGLE;

    ucp_worker_create(ucp_ctx, &wrkr_params, &wrkr);

    // ucp_worker_print_info(wrkr, stdout);

    ucp_worker_get_address(wrkr, &wrkr_addr, &wrkr_addr_sz);

    if (argc == 1) {    // Server
        conn_skt = server_connect();
    } else {            // Client
        conn_skt = client_connect(argv[1]);
    }

    exchange_worker_addr();
    prepare_ep_rkey();
    flush(true);    // Required for wire up

    socket_p2p_sync();

    if (argc == 1) {    // Server
        run_server();
    } else {            // Client
        run_client();
    }

    free(wrkr_rmt_addr);
    ucp_worker_release_address(wrkr, wrkr_addr);
    ucp_worker_destroy(wrkr);
    ucp_cleanup(ucp_ctx);

    close(conn_skt);
}
