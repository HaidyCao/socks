//
// Created by haidy on 2020/7/15.
//

#ifndef SOCKS_TIMER_H
#define SOCKS_TIMER_H

#include "multi_socks_epoll_server.h"

struct multi_socks_epoll_server_timer {
    MultiSocksBase *base;
//    MultiSocksEvent *event;
    int ev_fd;

    int tfd;
    size_t t;

    multi_socks_epoll_server_timer_cb cb;

    int need_close_fd;
    int oneshot;

    void *ctx;
};

MultiSocksTimer *MultiSocksTimer_new(int fd);

MultiSocksTimer *
multi_socks_epoll_server_event_set_timer_internal(MultiSocksEvent *ev, int64_t interval, int oneshot,
                                                  multi_socks_epoll_server_timer_cb cb, void *ctx);

void read_timeout_internal(MultiSocksTimer *timer, void *ctx);

#endif //SOCKS_TIMER_H
