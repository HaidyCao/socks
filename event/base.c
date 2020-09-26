//
// Created by haidy on 2020/7/15.
//

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>

#ifdef __APPLE__

#include <sys/event.h>

#elif __linux__ || __ANDROID__

#include <sys/epoll.h>

#endif

#ifdef EVENT_SSL

#include "openssl/ssl.h"

static bool ssl_init = false;
#else

#endif

#include "base.h"
#include "common.h"

MultiSocksBase *multi_socks_ev_base_new() {
    MultiSocksBase *base = (MultiSocksBase *) calloc(1, sizeof(MultiSocksBase));

    base->event_map = CSparseArray_new();
    base->dns_event_map = CSparseArray_new();
    base->timer_map = CSparseArray_new();
    base->buf_recycle_size = MULTI_SOCKS_DEFAULT_RECYCLE_BUF_SIZE;
    base->socks_listener_len = 0;
    base->listener_array = CSparseArray_new();

#ifdef EVENT_SSL
    if (!ssl_init) {
        SSL_load_error_strings();
        SSL_library_init();
    }

    base->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#endif

#ifdef __APPLE__
    base->e_fd = kqueue();
#elif __linux__ || __ANDROID__
    base->e_fd = epoll_create1(0);
#endif
    if (base->e_fd == -1) {
        free(base);
        return NULL;
    }
    return base;
}

EVENT_PUBLIC_API
int multi_socks_epoll_server_set_multi_thread_enable(MultiSocksBase *base, int enable) {
    if (base == NULL) {
        return -1;
    }

    if (enable) {
        if (base->event_map_mutex != NULL) {
            return 0;
        }

        base->event_map_mutex = calloc(1, sizeof(pthread_mutex_t));
        pthread_mutex_init(base->event_map_mutex, NULL);

        base->dns_event_map_mutex = calloc(1, sizeof(pthread_mutex_t));
        pthread_mutex_init(base->dns_event_map_mutex, NULL);

        base->timer_map_mutex = calloc(1, sizeof(pthread_mutex_t));
        pthread_mutex_init(base->timer_map_mutex, NULL);
    } else {
        if (base->event_map_mutex) {
            pthread_mutex_destroy(base->event_map_mutex);
            free(base->dns_event_map);
        }
        if (base->dns_event_map_mutex) {
            pthread_mutex_destroy(base->dns_event_map_mutex);
            free(base->dns_event_map_mutex);
        }
        if (base->timer_map_mutex) {
            pthread_mutex_destroy(base->timer_map_mutex);
            free(base->timer_map_mutex);
        }

        base->event_map_mutex = NULL;
        base->dns_event_map_mutex = NULL;
        base->timer_map_mutex = NULL;
    }
    return 0;
}

int turn_on_flags(int fd, int flags) {
    int current_flags;
    // 获取给定文件描述符现有的flag
    // 其中fcntl的第二个参数F_GETFL表示要获取fd的状态
    if ((current_flags = fcntl(fd, F_GETFL)) < 0)
        return -1;

    // 施加新的状态位
    current_flags |= flags;
    if (fcntl(fd, F_SETFL, current_flags) < 0)
        return -1;
    return 0;
}