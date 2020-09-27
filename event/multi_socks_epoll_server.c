#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <netdb.h>
#include <pthread.h>

#ifdef __APPLE__

#include <sys/event.h>

#elif __linux__ || __ANDROID__

#include <sys/epoll.h>
#include <sys/timerfd.h>

#endif

#include "lib/clib.h"
#include "c_dns.h"
#include "multi_socks_server.h"
#include "multi_socks_epoll_server.h"
#include "c_hash_map.h"
#include "../log.h"
#include "c_linked_list.h"
#include "c_hex_utils.h"
#include "buffer.h"
#include "event.h"
#include "timer.h"
#include "common.h"
#include "base.h"
#include "connect.h"

#ifdef EVENT_SSL

#include "openssl/ssl.h"

#endif

#ifdef EVENT_LOG_DISABLED

#undef LOGD
#undef LOGI
#undef LOGE

#define LOGD(fmt, ...)
#define LOGI(fmt, ...)
#define LOGE(fmt, ...)

#endif

#define EVENT_DEFAULT_READ_BUFFER 10240

void multi_socks_epoll_server_set_log_level(int level) {
    set_log_level(level);
}

struct multi_socks_epoll_ev_listener {
    int fd;
    void *ctx;
    connect_cb cb;

#ifdef EVENT_SSL
    SSL_CTX *ssl_ctx;
#endif
};

void MultiSocksEVListener_free(MultiSocksEVListener *l) {
    if (l == NULL) {
        return;
    }

    close(l->fd);

#ifdef EVENT_SSL
    if (l->ssl_ctx) {
        SSL_CTX_free(l->ssl_ctx);
    }
#endif

    free(l);
}

int multi_socks_epoll_ev_listener_get_fd(MultiSocksEVListener *l) {
    if (l)
        return l->fd;
    return -1;
}

struct multi_socks_epoll_server_dns_base {
    MultiSocksBase *base;

    CLinkedList *domain_list;
    CLinkedList *event_list;

    char exit;
};

EVENT_PUBLIC_API
MultiSocksDNSBase *multi_socks_epoll_server_new_dns_base(MultiSocksBase *base) {
    if (base == NULL)
        return NULL;

    MultiSocksDNSBase *dns_base = (MultiSocksDNSBase *) calloc(1, sizeof(MultiSocksDNSBase));
    dns_base->base = base;
    dns_base->exit = 0;
    dns_base->domain_list = c_linked_list_new();
    return dns_base;
}

EVENT_PUBLIC_API
int multi_socks_epoll_server_dns_free(MultiSocksDNSBase *base) {
    if (base == NULL)
        return -1;

    c_linked_list_free(base->domain_list);
    free(base);

    return 0;
}

static void disable_write(int e_fd, int fd);

EVENT_PUBLIC_API
int multi_socks_epoll_server_set_dns_server(MultiSocksBase *base, char *server) {
    if (base == NULL || server == NULL)
        return -1;

    if (strstr(server, ":")) {
        base->dns_server = strdup(server);
    } else {
        free(base->dns_server);
        asprintf(&base->dns_server, "%s:53", server);
    }

    base->dns_server_addr = (struct sockaddr *) calloc(1, sizeof(struct sockaddr));
    base->dns_server_addr_len = sizeof(struct sockaddr);
    if (parse_address(base->dns_server, base->dns_server_addr, (socklen_t *) &base->dns_server_addr_len) == -1) {
        LOGD("parse dns server failed: %s", server);
        return -1;
    }

    return 0;
}

static int event_accept(int fd, MultiSocksBase *base);

static void event_read(int fd, MultiSocksBase *base);

static void event_write(int fd, MultiSocksBase *base);

static MultiSocksEvent *get_event(MultiSocksBase *base, int fd) {
    MAP_LOCK(base->event_map_mutex);
    MultiSocksEvent *ev = CSparseArray_get(base->event_map, fd);
    MAP_UNLOCK(base->event_map_mutex);
    return ev;
}

static MultiSocksDNSEvent *get_dns_event(MultiSocksBase *base, int fd) {
    MAP_LOCK(base->dns_event_map_mutex);
    MultiSocksDNSEvent *ev = CSparseArray_get(base->dns_event_map, fd);
    MAP_UNLOCK(base->dns_event_map_mutex);
    return ev;
}

static MultiSocksTimer *get_timer(MultiSocksBase *base, int tfd) {
    MAP_LOCK(base->timer_map_mutex);
    void *timer = CSparseArray_get(base->timer_map, tfd);
    MAP_UNLOCK(base->timer_map_mutex);
    return timer;
}

static MultiSocksEVListener *
multi_socks_ev_listen_internal(MultiSocksBase *base, connect_cb cb, int fd, struct sockaddr *addr, int addr_len,
                               SSL_CTX *ssl_ctx, void *ctx) {
    if (fd == -1)
        fd = socket(addr->sa_family, SOCK_STREAM, 0);

    if (fd == -1) {
        LOGE("new fd failed: errno = %d, err = %s", errno, strerror(errno));
        return NULL;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, addr, addr_len);
    if (bind(fd, addr, addr_len) == -1) {
        LOGE("bind failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return NULL;
    }
    if (listen(fd, 20) == -1) {
        LOGE("listen failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return NULL;
    }
    if (turn_on_flags(fd, O_NONBLOCK)) {
        LOGD("turn_on_flags failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return NULL;
    }
#ifdef __APPLE__
    update_events(base->e_fd, fd, MULTI_SOCKS_READ_EVENT | MULTI_SOCKS_WRITE_EVENT, 0);
#elif __linux__ || __ANDROID__
    struct epoll_event event;
    event.data.fd = fd;
    event.events = EPOLLIN; // read | ET(edge-triggered)
    if (epoll_ctl(base->e_fd, EPOLL_CTL_ADD, fd, &event) == -1) {
        LOGD("epoll_ctl failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return NULL;
    }
#endif

    MultiSocksEVListener *l = (MultiSocksEVListener *) malloc(sizeof(MultiSocksEVListener));
    l->fd = fd;
    l->ctx = ctx;
    l->cb = cb;
#ifdef EVENT_SSL
    l->ssl_ctx = ssl_ctx;
#endif

    CSparseArray_put(base->listener_array, fd, l);
    base->socks_listener_len++;
    return l;
}

#ifdef EVENT_SSL
MultiSocksEVListener *
multi_socks_ev_ssl_listen(MultiSocksBase *base, connect_cb cb, int fd, struct sockaddr *addr, int addr_len,
                          SSL_CTX *ssl_ctx, void *ctx) {
    if (ssl_ctx == NULL) {
        return NULL;
    }

    return multi_socks_ev_listen_internal(base, cb, fd, addr, addr_len, ssl_ctx, ctx);
}
#endif

EVENT_PUBLIC_API
MultiSocksEVListener *
multi_socks_ev_listen(MultiSocksBase *base, connect_cb cb, int fd, struct sockaddr *addr, int addr_len, void *ctx) {
    return multi_socks_ev_listen_internal(base, cb, fd, addr, addr_len, NULL, ctx);
}

static void write_data(MultiSocksEvent *event, MultiSocksBuffer *buffer, struct sockaddr *addr, socklen_t addr_len);

static time_t MultiSocksEvent_get_timeout_interval(MultiSocksEvent *ev) {
    time_t ret = 0;
    time_t now = get_current_millisecond();

    if (ev->last_read_time > ev->last_write_time)
        ret = ev->write_timeout - (now - ev->last_write_time);
    else
        ret = ev->read_timeout - (now - ev->last_read_time);
    return ret;
}

static void write_timeout_internal(MultiSocksTimer *timer, void *ctx) {
    LOGD("timer = %p, event fd = %d", timer, timer->ev_fd);

    MAP_LOCK(timer->base->event_map_mutex);
    MultiSocksEvent *ev = CSparseArray_get(timer->base->event_map, timer->ev_fd);
    MAP_UNLOCK(timer->base->event_map_mutex);
    if (ev == NULL) {
        if (timer->base) {
            MAP_LOCK(timer->base->timer_map_mutex);
            CSparseArray_remove(timer->base->timer_map, timer->tfd);
            MAP_UNLOCK(timer->base->timer_map_mutex);
        }

        multi_socks_epoll_server_stop_timer(timer);
        return;
    }
    event_self_close(ev->fd, MULTI_SOCKS_EV_WRITE | MULTI_SOCKS_EV_TIME_OUT, ev);
}

EVENT_PUBLIC_API
int multi_socks_epoll_server_buffer_add_buffer(MultiSocksBuffer *out, MultiSocksBuffer *in) {
    if (out == NULL || in == NULL)
        return -1;

    // merge data
    MSB_LOCK(in,
             CLinkedList *list = NULL;
                     c_linked_list_move(&list, in->data_list);
                     size_t in_len = in->length;
                     in->length = 0;
    )


    MSB_LOCK(out,
             if (list != NULL) {
                 c_linked_list_merge(out->data_list, list);
                 out->length += in_len;

                 c_linked_list_free(list);
             }
    )

    if (out->event && write_enable(out->event) && out->event->out_buffer.length > 0 && out->event->addr == NULL)
        write_data(out->event, out, NULL, 0);
    return 0;
}

EVENT_PUBLIC_API
int multi_socks_epoll_server_buffer_sendto(MultiSocksBuffer *buf, char *data, size_t len, struct sockaddr *addr,
                                           socklen_t addr_len) {
    if (len == 0)
        return 0;
    if (multi_socks_epoll_server_buffer_write_internal(buf, data, len) == -1) {
        return -1;
    }
    if (!write_enable(buf->event)) {
        LOGD("enable write");
        multi_socks_epoll_server_event_enable_write(buf->event);
        return 0;
    }

    void *ev = get_event(buf->event->base, buf->event->fd);
    if (buf->event != NULL && write_enable(buf->event) && buf->event->fd != -1 && ev != NULL)
        write_data(buf->event, buf, addr, addr_len);
    else {
        LOGD("event = %p; fd = %d; find = %p", buf->event, buf->event->fd, ev);
    }
    return 0;
}

EVENT_PUBLIC_API
int multi_socks_epoll_server_buffer_write(MultiSocksBuffer *buf, char *data, size_t len) {
    if (len == 0)
        return 0;
    if (multi_socks_epoll_server_buffer_write_internal(buf, data, len) == -1) {
        return -1;
    }
    if (buf->event == NULL) {
        return 0;
    }

    void *ev = get_event(buf->event->base, buf->event->fd);
    if (buf->event != NULL && write_enable(buf->event) && buf->event->fd != -1 && ev != NULL)
        write_data(buf->event, buf, NULL, 0);
    return 0;
}

EVENT_PUBLIC_API
int multi_socks_ev_setcb(MultiSocksEvent *event, event_cb read_cb, event_cb write_cb, error_cb ev_cb, void *ctx) {
    if (event == NULL)
        return -1;

    event_cb old_read_cb = event->read_cb;

    event->read_cb = read_cb;
    event->write_cb = write_cb;
    event->err_cb = ev_cb;
    event->ctx = ctx;

    if (event->in_buffer.length > 0 && old_read_cb == NULL && read_cb != NULL)
        read_cb(event, ctx);

    if (event->out_buffer.length > 0 && write_enable(event))
        write_data(event, &event->out_buffer, NULL, 0);

    return 0;
}

static void write_data(MultiSocksEvent *event, MultiSocksBuffer *buffer, struct sockaddr *addr, socklen_t addr_len) {
    LOGD("ev = %p, fd = %d, out_buffer->len = %zu", event, event->fd, buffer->length);
    int fd = event->fd;
    MultiSocksBase *base = event->base;
    if (write_enable(event) && buffer->length > 0) {
        EventBuffer *header;
        while (1) {
            MSB_LOCK(buffer,
                     header = c_linked_list_get_header(buffer->data_list);
            )

            if (header == NULL) {
                break;
            }

            LOGD("header = %p", header);
#ifdef __APPLE__
            int wr;
#ifdef EVENT_SSL
            if (event->ssl) {
                wr = SSL_write(event->ssl, header->data + header->pos, header->len);
            } else
#endif
            if (addr) {
                wr = sendto(event->fd, header->data + header->pos, header->len, SO_NOSIGPIPE, addr, addr_len);
                LOGD("sendto %s %d data", sockaddr_to_string(addr, NULL, 0), wr);
            } else if (event->addr) {
                wr = sendto(event->fd, header->data + header->pos, header->len, SO_NOSIGPIPE, event->addr,
                            event->addr_len);
                LOGD("sendto %s %d data", sockaddr_to_string(event->addr, NULL, 0), wr);
            } else {
                wr = send(fd, header->data + header->pos, header->len, SO_NOSIGPIPE);
                LOGD("send %d data", wr);
            }
#elif __linux__ || __ANDROID__
            int wr;
#ifdef EVENT_SSL
            if (event->ssl) {
                wr = SSL_write(event->ssl, header->data + header->pos, header->len);
            } else
#endif
            if (event->addr) {
                wr = sendto(event->fd, header->data + header->pos, header->len, 0, event->addr, event->addr_len);
            } else {
                wr = send(fd, header->data + header->pos, header->len, MSG_NOSIGNAL);
            }

            if (wr == -1 && errno == ENOTSOCK) {
                wr = write(fd, header->data + header->pos, header->len);
            }
#endif
            if (wr == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    LOGD("update_events");
#ifdef __APPLE__
                    update_events(base->e_fd, fd, MULTI_SOCKS_READ_EVENT | MULTI_SOCKS_WRITE_EVENT, 0);
#elif __linux__ || __ANDROID__
                    struct epoll_event ev;
                    ev.data.fd = fd;
                    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
                    epoll_ctl(base->e_fd, EPOLL_CTL_MOD, fd, &ev);
#endif
                    set_write_disable(event);
                } else {
                    LOGI("errno = %d, strerror = %s", errno, strerror(errno));
                    event_self_close(fd, MULTI_SOCKS_EV_WRITE | MULTI_SOCKS_EV_ERROR, event);
                    return;
                }
                break;
            } else if (wr == 0) {
                event_self_close(fd, MULTI_SOCKS_EV_WRITE | MULTI_SOCKS_EV_ERROR, event);
                return;
            }
            MSB_LOCK(buffer, {
                c_linked_list_remove_header(buffer->data_list);
                buffer->length -= header->len;
            })
            EventBuffer_release(header);
        }

        LOGD("left size = %zu", buffer->length);
    } else if (!write_enable(event)) {
        LOGD("update_events");
#ifdef __APPLE__
        update_events(base->e_fd, fd, MULTI_SOCKS_READ_EVENT | MULTI_SOCKS_WRITE_EVENT, 0);
#elif __linux__ || __ANDROID__
        struct epoll_event ev;
        ev.data.fd = fd;
        ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
        epoll_ctl(base->e_fd, EPOLL_CTL_MOD, fd, &ev);
#endif
    }
}

static void event_write(int fd, MultiSocksBase *base) {
    LOGD("fd = %d", fd);
    MultiSocksEvent *event = get_event(base, fd);
    if (event == NULL) {
        LOGD("close fd = %d", fd);
        remove_event(base->e_fd, fd);

        close(fd);
        return;
    }
    LOGD("ev_fd = %d, out buffer len = %zu", event->fd, event->out_buffer.length);
    disable_write(base->e_fd, fd);

#ifdef EVENT_SSL
    if (event->ssl && event->ssl_handshaking) {
        int r = SSL_do_handshake(event->ssl);
        if (r != 1) {
            int err = SSL_get_error(event->ssl, r);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                LOGE("SSL error: %s", ERR_error_string(err, NULL));
            }
            return;
        }
        event->ssl_handshaking = false;
    }
#endif

    set_write_enable(event);
    if (event->out_buffer.length == 0)
        return;

    if (event->addr == NULL)
        write_data(event, &event->out_buffer, NULL, 0);
    else {
        if (event->udp_out_buf_map) {
            struct sockaddr_storage addr;
            C_HASH_MAP_FOR(event->udp_out_buf_map, {
                socklen_t addr_len = sizeof(addr);
                if (parse_address(k, (struct sockaddr *) &addr, &addr_len)) {
                    continue;
                }

                write_data(event, v, (struct sockaddr *) &addr, addr_len);
            })
        } else if (event->addr) {
            write_data(event, &event->out_buffer, event->addr, event->addr_len);
        }
    }
}

static void event_read(int fd, MultiSocksBase *base) {
    LOGD("fd = %d", fd);
    MultiSocksEvent *event = get_event(base, fd);
    if (event == NULL) {
        LOGD("close fd = %d", fd);
        remove_event(base->e_fd, fd);
        close(fd);
        return;
    }
    LOGD("ev_fd = %d", event->fd);

#ifdef EVENT_SSL
    if (event->ssl && event->ssl_handshaking) {
        int r = SSL_do_handshake(event->ssl);
        if (r != 1) {
            int err = SSL_get_error(event->ssl, r);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                LOGE("SSL error: %s", ERR_error_string(err, NULL));
            }
            return;
        }
        event->ssl_handshaking = false;
    }
#endif

    set_write_disable(event);
    static __thread char buf[EVENT_DEFAULT_READ_BUFFER];
    ssize_t n;
    int err_number = 0;

    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    while (1) {
#ifdef EVENT_SSL
        if (event->ssl) {
            n = SSL_read(event->ssl, buf, EVENT_DEFAULT_READ_BUFFER);
        } else
#endif
        {
            if (event->addr) {
                bzero(&addr, sizeof(addr));
                n = recvfrom(fd, buf, EVENT_DEFAULT_READ_BUFFER, 0, (struct sockaddr *) &addr, &addr_len);
                LOGD("read len = %zd from %s", n, sockaddr_to_string((struct sockaddr *) &addr, NULL, 0));
            } else {
                n = read(fd, buf, EVENT_DEFAULT_READ_BUFFER);
                LOGD("read len = %zd", n);
            }
        }

        if (n <= 0) {
            err_number = errno;
            break;
        }

        if (event->addr) {
            char *address = sockaddr_to_string((struct sockaddr *) &addr, NULL, 0);
            MultiSocksBuffer *buffer = c_hash_map_get(event->udp_in_buf_map, address);
            if (buffer == NULL) {
                buffer = MultiSocksBuffer_new();
                buffer->event = event;
                c_hash_map_put(event->udp_in_buf_map, address, buffer);
            }
            multi_socks_epoll_server_buffer_write(buffer, buf, (size_t) n);
            if (event->udp_read_cb) {
                event->udp_read_cb(event, buffer, (struct sockaddr *) &addr, addr_len, event->ctx);
            }
        } else {
            multi_socks_epoll_server_buffer_write(&event->in_buffer, buf, (size_t) n);
            if (event->read_cb)
                event->read_cb(event, event->ctx);
        }
        errno = 0;
        event = get_event(base, fd);
        if (event == NULL) {
            LOGD("event is freed");
            return;
        }

        if (read_enable(event)) {
            continue;
        }
        break;
    }

    event = get_event(base, fd);
    if (n > 0 || (n == -1 && (err_number == EAGAIN || err_number == EWOULDBLOCK))) {
        if (event == NULL)
            return;
        if (event->timeout && event->read_timeout > 0) {
            LOGD("reset read timeout");
            MAP_LOCK(base->timer_map_mutex);
            CSparseArray_remove(base->timer_map, event->timeout->tfd);
            MAP_UNLOCK(base->timer_map_mutex);
            multi_socks_epoll_server_stop_timer(event->timeout);

            event->last_read_time = get_current_millisecond();
            int64_t t = MultiSocksEvent_get_timeout_interval(event);
            event->timeout = multi_socks_epoll_server_event_set_timer_internal(event, t, 1, read_timeout_internal,
                                                                               NULL);
        } else if (event->timeout != NULL && event->write_timeout == 0) {
            MAP_LOCK(base->timer_map_mutex);
            CSparseArray_remove(event->base->timer_map, event->timeout->tfd);
            MAP_UNLOCK(base->timer_map_mutex);
            multi_socks_epoll_server_stop_timer(event->timeout);
            event->timeout = NULL;
        }

        // make freed by outside
        write_data(event, &event->out_buffer, NULL, 0);
        return;
    }
    LOGD("n = %zd, errno = %d, strerror = %s", n, errno, strerror(errno));
    if (event) {
        set_write_disable(event);
        if (event->in_buffer.length > 0 && event->read_cb) {
            event->read_cb(event, event->ctx);
        }

        event = get_event(base, fd);
        if (event) {
            event_self_close(fd, MULTI_SOCKS_EV_READ_AND_EOF, event);
        }
    } else {
        close(fd);
    }
}

static int event_accept(int fd, MultiSocksBase *base) {
    LOGD("accept: listener fd = %d", fd);
    struct sockaddr raddr;
    socklen_t rlen = sizeof(struct sockaddr);
    int rfd = accept(fd, &raddr, &rlen);
    if (rfd == -1) {
        if (errno != EAGAIN) {
            LOGE("accept failed: errno = %d, errmsg: %s", errno, strerror(errno));
        }
        return -1;
    }

    if (turn_on_flags(rfd, O_NONBLOCK)) {
        LOGD("turn_on_flags failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return -1;
    }
    LOGD("accept fd = %d", rfd);

#ifdef __APPLE__
    update_events(base->e_fd, rfd, MULTI_SOCKS_READ_EVENT | MULTI_SOCKS_WRITE_EVENT, 0);
#elif __linux__ || __ANDROID__
    struct epoll_event ev;
    ev.data.fd = rfd;
    ev.events = EPOLLIN | EPOLLET | EPOLLOUT;
    if (epoll_ctl(base->e_fd, EPOLL_CTL_ADD, rfd, &ev) == -1) {
        LOGE("epoll_ctl failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return 0;
    }
#endif

    MultiSocksEvent *event = MultiSocksEvent_new(base, rfd, NULL);
    event->connect = 0;
    LOGD("accept event = %p", event);

    MAP_LOCK(base->event_map_mutex);
    CSparseArray_put(base->event_map, rfd, event);
    MAP_UNLOCK(base->event_map_mutex);

    MultiSocksEVListener *l = CSparseArray_get(base->listener_array, fd);
    if (l) {
#ifdef EVENT_SSL
        if (l->ssl_ctx) {
            event->ssl_handshaking = true;
            event->ssl = SSL_new(l->ssl_ctx);
            SSL_set_fd(event->ssl, rfd);
            SSL_set_accept_state(event->ssl);
        }
#endif

        l->cb(l, rfd, &raddr, rlen, event, l->ctx);
    }

    return 0;
}

EVENT_PUBLIC_API
MultiSocksEvent *
multi_socks_listen(MultiSocksBase *base, int fd, event_cb read_cb, event_cb write_cb, error_cb event_cb, void *ctx) {
    if (base == NULL)
        return NULL;

#ifdef __APPLE__
    struct kevent kev[1];
    EV_SET(&kev[0], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, (void *) (intptr_t) fd);
    if (kevent(base->e_fd, kev, 1, NULL, 0, NULL) == -1) {
        LOGD("kevent failed: errno = %d, errmsg: %s", errno, strerror(errno));
        close(fd);
        return NULL;
    }
#elif __linux__ || __ANDROID__
    struct epoll_event event;
    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLET | EPOLLOUT; // read | ET(edge-triggered)
    if (epoll_ctl(base->e_fd, EPOLL_CTL_ADD, fd, &event) == -1) {

        close(fd);
        LOGD("epoll_ctl failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return NULL;
    }
#endif

    MultiSocksEvent *ev = MultiSocksEvent_new(base, fd, ctx);
    ev->connect = 0;
    ev->err_cb = event_cb;
    ev->read_cb = read_cb;
    ev->write_cb = write_cb;

    MAP_LOCK(base->event_map_mutex);
    CSparseArray_put(base->event_map, fd, ev);
    MAP_UNLOCK(base->event_map_mutex);

    return ev;
}

static void disable_write(int e_fd, int fd) {
    LOGD("update_events");
#ifdef __APPLE__
    update_events(e_fd, fd, MULTI_SOCKS_READ_EVENT, 1);
#elif __linux__ || __ANDROID__
    struct epoll_event event;
    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLET; // read | ET(edge-triggered)
    if (epoll_ctl(e_fd, EPOLL_CTL_MOD, fd, &event) == -1) {
        LOGD("epoll_ctl failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return;
    }
#endif
}

static void handle_dns_read(MultiSocksDNSEvent *event) {
    char dns_buf[MS_BUFSIZE];
    size_t packet_len = sizeof(dns_buf);

    ssize_t recv_len = recvfrom(event->dns_fd, dns_buf, packet_len, 0, event->base->dns_server_addr,
                                (socklen_t *) &event->base->dns_server_addr_len);
    if (recv_len < 0) {
        LOGE("recvfrom %s failed: errno = %d, strerror = %s",
             sockaddr_to_string(event->base->dns_server_addr, NULL, 0), errno, strerror(errno));
        multi_socks_epoll_server_dns_event_free(event);
        return;
    }
    LOGD("event = %p, dns_fd = %d", event, event->dns_fd);
    struct hostent *host = NULL;
    if (c_dns_parse_a(dns_buf, recv_len, &host) != 0) {
        LOGE("parse %s failed: errno = %d, strerror = %s",
             sockaddr_to_string(event->base->dns_server_addr, NULL, 0), errno, strerror(errno));
        multi_socks_epoll_server_dns_event_free(event);
        return;
    }
    LOGD("dns event = %p", event);

    struct sockaddr addr;
    size_t addr_len = sizeof(addr);
    if (c_dns_parse_first_ip(host, &addr, &addr_len, event->port) == -1) {
        c_dns_free_hostent(host);
        LOGE("c_dns_parse_first_ip failed: errno = %d, strerror = %s", errno, strerror(errno));
        multi_socks_epoll_server_dns_event_free(event);
        return;
    }
    c_dns_free_hostent(host);

    MultiSocksBase *base = event->base;
    MultiSocksEvent *ev = event->event;
    LOGD("dns success: address = %s, fd = %d", sockaddr_to_string(&addr, NULL, 0), ev->fd);
    int ssl = event->ssl;

    event->event->dns_ev = NULL;
    event->event = NULL;
    multi_socks_epoll_server_dns_event_free(event);
    multi_socks_epoll_server_connect_internal(base, ev, ev->fd, ev->type, &addr, addr_len, ssl, ev->ctx);
}

static void handle_dns_write(MultiSocksDNSEvent *event) {
    LOGD("dns fd = %d, domain = %s", event->dns_fd, event->domain);
    char dns_buf[MS_BUFSIZE];
    ssize_t packet_len = c_dns_pack(event->domain, dns_buf, MS_BUFSIZE, C_DNS_QTYPE_A);
    if (packet_len == -1 && event->event->err_cb) {
        int fd = event->event->fd;
        MultiSocksBase *base = event->base;
        event->event->err_cb(event->event, MULTI_SOCKS_EV_ERROR, event->event->ctx);
        event->event = get_event(base, fd);
        LOGD("dns_pack failed");
        multi_socks_epoll_server_dns_event_free(event);
        return;
    }

    int r = sendto(event->dns_fd, dns_buf, packet_len, 0, event->base->dns_server_addr,
                   event->base->dns_server_addr_len);
    if (r == -1) {
        LOGD("sendto failed errno = %d, strerror = %s", errno, strerror(errno));
        multi_socks_epoll_server_dns_event_free(event);
        return;
    }
    event->data_has_send = 1;
    disable_write(event->base->e_fd, event->dns_fd);
}

EVENT_PUBLIC_API
int multi_socks_ev_loop(MultiSocksBase *base) {
    if (base == NULL)
        return -1;

#ifdef __APPLE__
    int kq = base->e_fd;
    while (1) {

        struct kevent events[MULTI_SOCKS_MAX_EVENTS];
//        LOGD("wait new events");
        int n = kevent(kq, NULL, 0, events, MULTI_SOCKS_MAX_EVENTS, NULL);
//        LOGD("kevent return: n = %d", n);
        if (n == -1) {
            LOGD("errno = %d, err = %s", errno, strerror(errno));
            continue;
        }
        size_t i;
        for (i = 0; i < n; i++) {
            if (base->e_fd == -1) {
                LOGI("loop is finished");
                return -1;
            }
            int event = events[i].filter;
            if (event == EVFILT_TIMER) {
//                LOGD("event is timer");
                int tfd = (int) (intptr_t) events[i].udata;
                MultiSocksTimer *timer = get_timer(base, tfd);
                if (timer == NULL) {
                    LOGE("get timer failed: tfd = %d", tfd);
                    continue;
                }
                multi_socks_epoll_server_timer_cb cb = timer->cb;

                if (cb == write_timeout_internal || cb == read_timeout_internal) {
                    LOGD("timeout: tfd = %d, event fd = %d", tfd, timer->ev_fd);
                    cb(timer, timer->ctx);
                    timer = get_timer(base, tfd);

                    if (timer) {
                        multi_socks_epoll_server_stop_timer(timer);
                    }
                    continue;
                }

                void *t_ctx = timer->ctx;
                if (timer->oneshot) {
                    MultiSocksEvent *ev = get_event(base, timer->ev_fd);
                    multi_socks_epoll_server_stop_timer(timer);
                    if (ev)
                        ev->timer = NULL;
                    timer = NULL;
                }
                if (cb) {
                    cb(timer, t_ctx);
                }
                continue;
            }
            int efd = (int) (intptr_t) events[i].udata;
            LOGD("efd = %d, event = %d", efd, event);

            if (event == EVFILT_READ) {
                MultiSocksEVListener *l = CSparseArray_get(base->listener_array, efd);
                if (l) {
                    while (event_accept(efd, base) != -1) {
                        LOGD("accept next");
                    }
                } else {
                    MultiSocksDNSEvent *dns_event = get_dns_event(base, efd);
                    if (dns_event != NULL) {
                        LOGD("v = %p, dns_fd = %d", dns_event, dns_event->dns_fd);
                        handle_dns_read(dns_event);
                        continue;
                    }

                    event_read(efd, base);
                }
            } else if (event == EVFILT_WRITE) {
                MultiSocksDNSEvent *dns_event = get_dns_event(base, efd);
                if (dns_event != NULL) {
                    LOGD("dns event");
                    if (dns_event->data_has_send)
                        continue;
                    LOGD("v = %p, dns_fd = %d", dns_event, dns_event->dns_fd);

                    if (dns_event->base == NULL)
                        dns_event->base = base;
                    if (dns_event->event->base == NULL)
                        dns_event->event->base = NULL;

                    handle_dns_write(dns_event);
                    continue;
                }

                MultiSocksEvent *ev = get_event(base, efd);
                if (ev == NULL) {
                    LOGD("event is null: %d", efd);
                    close(efd);
                    continue;
                }
                if (ev->connect) {
                    ev->connect = 0;
                    // on connect

                    if (ev->err_cb) {
                        ev->err_cb(ev, MULTI_SOCKS_EV_CONNECT, ev->ctx);
                        ev = get_event(base, efd);

                        if (ev == NULL) continue;
                    }

                    LOGD("onconnect: fd = %d, read_timeout = %d, write_timeout = %d", efd, ev->read_timeout,
                         ev->write_timeout);
                    if (ev->read_timeout > 0 || ev->write_timeout > 0)
                        multi_socks_epoll_server_event_set_timeout(ev, ev->read_timeout, ev->write_timeout);
                }
                event_write(efd, base);
            } else {
                LOGD("unknown event = %d", event);
            }
        }
    }
#elif __linux__ || __ANDROID__
    struct epoll_event *events;
    events = (struct epoll_event *) calloc(MULTI_SOCKS_MAX_EVENTS, sizeof(struct epoll_event));
    while (1) {
        LOGD("epoll_wait");
        int n = epoll_wait(base->e_fd, events, MULTI_SOCKS_MAX_EVENTS, -1);
        if (n == -1) {
            LOGE("epoll_wait failed: errno = %d, errmsg: %s", errno, strerror(errno));
            return -1;
        }
        if (n > 0) {
            LOGD("epoll_wait result n = %d", n);
        }
        int i;
        for (i = 0; i < n; i++) {
            uint32_t e = events[i].events;
            int e_fd = events[i].data.fd;
            LOGD("event[%d] = %x, event_fd = %d", i, e, e_fd);
            if ((e & (uint32_t) EPOLLERR) || (e & (uint32_t) EPOLLHUP)) {
                LOGD("epoll error: events = %x", e);
                MultiSocksEvent *ev = get_event(base, e_fd);
                if (ev)
                    event_self_close(e_fd, MULTI_SOCKS_EV_ERROR, ev);
                else {
                    MAP_LOCK(base->dns_event_map_mutex);
                    MultiSocksDNSEvent *dns_ev = CSparseArray_get(base->dns_event_map, e_fd);
                    MAP_UNLOCK(base->dns_event_map_mutex);
                    if (dns_ev != NULL) {
                        multi_socks_epoll_server_dns_event_free(dns_ev);
                    }
                }
                continue;
            }
            MultiSocksEVListener *l = CSparseArray_get(base->listener_array, e_fd);

            if (l) {
                while (event_accept(e_fd, base) != -1) {
                    LOGD("accept next");
                }
            } else {
                LOGD("events = %x, read = %d, write = %d, et = %d", e, e & (uint32_t) EPOLLIN, e & (uint32_t) EPOLLOUT,
                     e & (uint32_t) EPOLLET);
                if (e & (uint32_t) EPOLLIN) {
                    MAP_LOCK(base->dns_event_map_mutex);
                    MultiSocksDNSEvent *dns_event = (MultiSocksDNSEvent *) CSparseArray_get(base->dns_event_map, e_fd);
                    MAP_UNLOCK(base->dns_event_map_mutex);
                    if (dns_event != NULL) {
                        handle_dns_read(dns_event);
                        continue;
                    }

                    // timer
                    MultiSocksTimer *t = get_timer(base, e_fd);
                    if (t) {
                        if (t->tfd != e_fd) {
                            MAP_LOCK(base->timer_map_mutex);
                            CSparseArray_remove(base->timer_map, e_fd);
                            MAP_UNLOCK(base->timer_map_mutex);
                            multi_socks_epoll_server_stop_timer(t);
                            continue;
                        }
                        multi_socks_epoll_server_timer_cb cb = t->cb;

                        if (cb == write_timeout_internal || cb == read_timeout_internal) {
                            cb(t, t->ctx);
                            continue;
                        }

                        void *t_ctx = t->ctx;
                        int oneshot = t->oneshot;
                        if (oneshot) {
                            MultiSocksEvent *ev = get_event(base,t->ev_fd);
                            multi_socks_epoll_server_stop_timer(t);
                            if (ev)
                                ev->timer = NULL;
                            t = NULL;
                        }

                        if (cb) {
                            cb(t, t_ctx);
                        }

                        if (oneshot) {
                            continue;
                        }

                        // check timer is freed
                        if (t->tfd == 0)
                            continue;

                        uint64_t exp;
                        int tr = read(t->tfd, &exp, sizeof(uint64_t));
                        if (tr != sizeof(uint64_t))
                            multi_socks_epoll_server_stop_timer(t);
                        else
                            LOGD("timer read result = %ld", (long) exp);

                        continue;
                    }

                    event_read(e_fd, base);
                }
                if (e & (uint32_t) EPOLLOUT) {
                    MultiSocksDNSEvent *dns_event = get_dns_event(base, e_fd);
                    if (dns_event != NULL) {
                        if (dns_event->data_has_send)
                            continue;
                        handle_dns_write(dns_event);
                        continue;
                    }

                    MultiSocksEvent *ev = get_event(base, e_fd);
                    if (ev == NULL) {
                        LOGD("event is null");
                        remove_event(base->e_fd, e_fd);
                        close(e_fd);
                        continue;
                    }
                    if (ev->connect) {
                        LOGD("onconnect: fd = %d", e_fd);
                        // on connect
                        ev->connect = 0;

                        if (ev->err_cb) {
                            ev->err_cb(ev, MULTI_SOCKS_EV_CONNECT, ev->ctx);
                            ev = get_event(base, e_fd);
                        }
                    }
                    event_write(e_fd, base);
                }
            }
        }
    }

#endif
}

EVENT_PUBLIC_API
void multi_socks_base_free(MultiSocksBase *base) {
    CSparseArray_clear(base->listener_array, (c_sparse_array_value_free_cb) MultiSocksEVListener_free);

    close(base->e_fd);
    base->e_fd = -1;
}