#ifndef MULTI_SOCKS_EPOLL_SERVER_H
#define MULTI_SOCKS_EPOLL_SERVER_H

#ifdef __cplusplus

extern "C"
{

#endif

#include <sys/socket.h>

#ifdef EVENT_SSL

#include "openssl/ssl.h"

#endif

// MultiSocksBase
struct multi_socks_epoll_server_base;
typedef struct multi_socks_epoll_server_base MultiSocksBase;

struct multi_socks_epoll_server_timer;
typedef struct multi_socks_epoll_server_timer MultiSocksTimer;

typedef void (*multi_socks_epoll_server_timer_cb)(MultiSocksTimer *timer, void *ctx);

int multi_socks_epoll_server_stop_timer(MultiSocksTimer *timer);

int multi_socks_epoll_server_set_multi_thread_enable(MultiSocksBase *base, int enable);

struct multi_socks_epoll_server_dns_base;
typedef struct multi_socks_epoll_server_dns_base MultiSocksDNSBase;

MultiSocksDNSBase *multi_socks_epoll_server_new_dns_base(MultiSocksBase *base);

int multi_socks_epoll_server_dns_free(MultiSocksDNSBase *base);

int multi_socks_epoll_server_set_dns_server(MultiSocksBase *base, char *server);

MultiSocksBase *multi_socks_ev_base_new();

int multi_socks_ev_loop(MultiSocksBase *base);

void multi_socks_base_free(MultiSocksBase *base);

struct multi_socks_epoll_server_event;
typedef struct multi_socks_epoll_server_event MultiSocksEvent;

void *multi_socks_epoll_server_event_get_ctx(MultiSocksEvent *ev);

int multi_socks_epoll_server_event_get_fd(MultiSocksEvent *ev);

MultiSocksBase *multi_socks_epoll_server_event_get_base(MultiSocksEvent *ev);

void multi_socks_epoll_server_event_enable_read(MultiSocksEvent *ev);

void multi_socks_epoll_server_event_enable_write(MultiSocksEvent *ev);

void multi_socks_epoll_server_event_disable_read(MultiSocksEvent *ev);

MultiSocksTimer *
multi_socks_epoll_server_event_set_timer(MultiSocksEvent *ev, int64_t interval, multi_socks_epoll_server_timer_cb cb,
                                         void *ctx);

MultiSocksTimer *multi_socks_epoll_server_event_set_timer_oneshot(MultiSocksEvent *ev, int64_t interval,
                                                                  multi_socks_epoll_server_timer_cb cb, void *ctx);

MultiSocksTimer *
multi_socks_epoll_server_event_set_timeout(MultiSocksEvent *ev, int64_t read_timeout, int64_t write_timeout);

void multi_socks_epoll_server_event_free(MultiSocksEvent *ev);


MultiSocksEvent *
multi_socks_epoll_server_connect(MultiSocksBase *base, int fd, struct sockaddr *addr, size_t addr_len, void *ctx);

MultiSocksEvent *
multi_socks_epoll_server_ssl_connect(MultiSocksBase *base, int fd, struct sockaddr *addr, size_t addr_len, void *ctx);

MultiSocksEvent *
multi_socks_epoll_server_udp(MultiSocksBase *base, int fd, struct sockaddr *addr, size_t addr_len, void *ctx);

MultiSocksEvent *
multi_socks_epoll_server_connect_hostname(MultiSocksBase *base, int fd, char *host, int port, void *ctx);

MultiSocksEvent *
multi_socks_epoll_server_ssl_connect_hostname(MultiSocksBase *base, int fd, char *host, int port, void *ctx);

MultiSocksEvent *multi_socks_epoll_server_udp_hostname(MultiSocksBase *base, int fd, char *host, int port, void *ctx);

// MultiSocksEVListener
struct multi_socks_epoll_ev_listener;
typedef struct multi_socks_epoll_ev_listener MultiSocksEVListener;

// callback
typedef void (*connect_cb)(MultiSocksEVListener *l, int fd, struct sockaddr *addr, int addr_len, MultiSocksEvent *event,
                           void *ctx);

typedef void (*event_cb)(MultiSocksEvent *ev, void *ctx);

typedef void (*error_cb)(MultiSocksEvent *ev, int what, void *ctx);

MultiSocksEvent *
multi_socks_listen(MultiSocksBase *base, int fd, event_cb read_cb, event_cb write_cb, error_cb event_cb, void *ctx);

int multi_socks_epoll_ev_listener_get_fd(MultiSocksEVListener *l);

MultiSocksEVListener *
multi_socks_ev_listen(MultiSocksBase *base, connect_cb cb, int fd, struct sockaddr *addr, int addr_len, void *ctx);

#ifdef EVENT_SSL

MultiSocksEVListener *
multi_socks_ev_ssl_listen(MultiSocksBase *base, connect_cb cb, int fd, struct sockaddr *addr, int addr_len,
                          SSL_CTX *ssl_ctx, void *ctx);

#endif

int multi_socks_ev_setcb(MultiSocksEvent *event, event_cb read_cb, event_cb write_cb, error_cb event_cb, void *ctx);

struct multi_socks_epoll_server_buffer;
typedef struct multi_socks_epoll_server_buffer MultiSocksBuffer;

typedef void (*udp_event_cb)(MultiSocksEvent *ev, MultiSocksBuffer *buffer, struct sockaddr *addr, socklen_t addr_len,
                             void *ctx);

int multi_socks_ev_udp_setcb(MultiSocksEvent *event, udp_event_cb read_cb, udp_event_cb write_cb, error_cb event_cb,
                             void *ctx);

MultiSocksBuffer *MultiSocksBuffer_new();

void MultiSocksBuffer_free(MultiSocksBuffer *buffer);

int multi_socks_epoll_server_buffer_add_buffer(MultiSocksBuffer *out, MultiSocksBuffer *in);

size_t multi_socks_epoll_server_buffer_get_length(MultiSocksBuffer *buf);

ssize_t multi_socks_epoll_server_buffer_copyout(MultiSocksBuffer *buf, char *data, size_t len);

ssize_t multi_socks_epoll_server_buffer_move_out(MultiSocksBuffer *buf, char **data, size_t *len);

int multi_socks_epoll_server_buffer_remove(MultiSocksBuffer *buf, size_t len);

MultiSocksBuffer *multi_socks_ev_get_input(MultiSocksEvent *event);

MultiSocksBuffer *multi_socks_ev_get_output(MultiSocksEvent *event);

MultiSocksBuffer *multi_socks_ev_udp_get_output(MultiSocksEvent *event, struct sockaddr *addr, socklen_t addr_len);

int multi_socks_epoll_server_buffer_sendto(MultiSocksBuffer *buf, char *data, size_t len, struct sockaddr *addr,
                                           socklen_t addr_len);

int multi_socks_epoll_server_buffer_write(MultiSocksBuffer *buf, char *data, size_t len);

void multi_socks_epoll_server_set_log_level(int level);

#ifdef __cplusplus
}
#endif

#define MULTI_SOCKS_EV_READ 0x01
#define MULTI_SOCKS_EV_WRITE 0x02
#define MULTI_SOCKS_EV_TIME_OUT 0x04
#define MULTI_SOCKS_EV_ERROR 0x08
#define MULTI_SOCKS_EV_EOF 0x10
#define MULTI_SOCKS_EV_CONNECT 0x20

#define MULTI_SOCKS_EV_READ_AND_EOF ((unsigned int)MULTI_SOCKS_EV_READ | (unsigned int)MULTI_SOCKS_EV_EOF)

#define MULTI_SOCKS_IS_EOF(what) (((unsigned int) what & (unsigned int)MULTI_SOCKS_EV_EOF) != 0)
#define MULTI_SOCKS_IS_CONNECT(what) (((unsigned int) what & (unsigned int)MULTI_SOCKS_EV_CONNECT) != 0)
#define MULTI_SOCKS_IS_ERROR(what) (((unsigned int) what & (unsigned int)MULTI_SOCKS_EV_ERROR) != 0)

#endif