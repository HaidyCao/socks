//
// Created by haidy on 2020/7/15.
//

#ifndef SOCKS_BASE_H
#define SOCKS_BASE_H

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "multi_socks_epoll_server.h"
#include "../lib/c_sparse_array.h"

#ifdef EVENT_SSL

#include "openssl/ssl.h"

#endif

struct multi_socks_epoll_server_base {
    int e_fd;

    CSparseArray *listener_array;
    size_t socks_listener_len;
    CSparseArray *event_map;
    CSparseArray *dns_event_map;
    CSparseArray *timer_map;
    size_t buf_recycle_size;

    char *dns_server;
    struct sockaddr *dns_server_addr;
    size_t dns_server_addr_len;

    pthread_mutex_t *event_map_mutex;
    pthread_mutex_t *dns_event_map_mutex;
    pthread_mutex_t *timer_map_mutex;

#ifdef EVENT_SSL
    SSL_CTX *ssl_ctx;

#endif
};

#ifdef EVENT_SINGLE_THREAD
#define MAP_LOCK(mutex)
#define MAP_UNLOCK(mutex)
#else
#define MAP_LOCK(mutex) if (mutex) pthread_mutex_lock(mutex)
#define MAP_UNLOCK(mutex) if (mutex) pthread_mutex_unlock(mutex)
#endif

int turn_on_flags(int fd, int flags);

#endif //SOCKS_BASE_H
