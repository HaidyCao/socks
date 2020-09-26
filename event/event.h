//
// Created by haidy on 2020/7/15.
//

#ifndef SOCKS_EVENT_H
#define SOCKS_EVENT_H

#include <stdbool.h>

#include "multi_socks_epoll_server.h"
#include "c_hash_map.h"
#include "buffer.h"

#ifdef EVENT_SSL

#include "openssl/ssl.h"
#include "openssl/err.h"

#define EVENT_EXT       \
SSL *ssl;               \
bool ssl_handshaking;
#else
#define EVENT_EXT
#endif

typedef struct multi_socks_epoll_server_dns_event {
    MultiSocksBase *base;
    MultiSocksEvent *event;
    int dns_fd;
    char data_has_send;

    char *domain;
    int port;
#ifdef EVENT_SSL
    int ssl;
#endif
} MultiSocksDNSEvent;

struct multi_socks_epoll_server_event {
    MultiSocksBase *base;
    MultiSocksTimer *timer;

    int fd;
    int type;           // tcp or udp
    char connect;
    u_char ev;          // 1: read 2: write
    MultiSocksBuffer in_buffer;
    MultiSocksBuffer out_buffer;
    CHashMap *udp_in_buf_map;
    CHashMap *udp_out_buf_map;

    struct sockaddr *addr;
    size_t addr_len;

    int fd_in;
    int fd_in6;

    void *ctx;

    event_cb read_cb;
    udp_event_cb udp_read_cb;
    event_cb write_cb;
    udp_event_cb udp_write_cb;
    error_cb err_cb;

    int64_t read_timeout;
    int64_t write_timeout;
    int64_t conn_timeout;

    time_t last_read_time;
    time_t last_write_time;
    MultiSocksTimer *timeout;

    MultiSocksDNSEvent *dns_ev;
    EVENT_EXT
};

MultiSocksEvent *MultiSocksEvent_new(MultiSocksBase *base, int fd, void *ctx);

void remove_event(int e_fd, int fd);

void multi_socks_epoll_server_dns_event_free(MultiSocksDNSEvent *event);

void event_self_close(int fd, int what, MultiSocksEvent *event);

#endif //SOCKS_EVENT_H
