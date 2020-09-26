//
// Created by haidy on 2020/7/15.
//
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>

#ifdef __APPLE__

#include <sys/event.h>

#elif __linux__ || __ANDROID__

#include <sys/epoll.h>
#include <sys/timerfd.h>

#endif

#include "event.h"
#include "connect.h"
#include "multi_socks_epoll_server.h"
#include "../log.h"
#include "clib.h"
#include "base.h"
#include "common.h"

MultiSocksEvent *
multi_socks_epoll_server_connect_internal(MultiSocksBase *base, MultiSocksEvent *ev, int fd, int fd_type,
                                          struct sockaddr *addr, size_t addr_len, int ssl, void *ctx) {
    if (base == NULL) {
        if (ev)
            multi_socks_epoll_server_event_free(ev);
        return NULL;
    }

    LOGD("fd = %d, address = %s", fd, sockaddr_to_string(addr, NULL, 0));

    if (fd == -1) {
        if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
            LOGD("unknown fd type = %d", addr->sa_family);
            multi_socks_epoll_server_event_free(ev);
            return NULL;
        }

        if (ev) {
            if (addr->sa_family == AF_INET) {
                fd = ev->fd_in;
                close(ev->fd_in6);
            } else {
                fd = ev->fd_in6;
                close(ev->fd_in);
            }
            ev->fd_in = 0;
            ev->fd_in6 = 0;
        } else {
            if (fd_type == SOCK_DGRAM)
                fd = socket(addr->sa_family, fd_type, IPPROTO_UDP);
            else
                fd = socket(addr->sa_family, fd_type, 0);
        }

        LOGD("new fd = %d, fd type = %d, addr_len = %zu", fd, fd_type, addr_len);
    }

    if (fd == -1) {
        if (ev != NULL && ev->err_cb) {
            ev->err_cb(ev, MULTI_SOCKS_EV_ERROR | MULTI_SOCKS_EV_CONNECT, ctx);
            MAP_LOCK(base->event_map_mutex);
            ev = CSparseArray_get(base->event_map, fd);
            MAP_UNLOCK(base->event_map_mutex);
            multi_socks_epoll_server_event_free(ev);
        }

        LOGD("socket failed: errno = %d, strerror = %s", errno, strerror(errno));
        return NULL;
    }

    if (turn_on_flags(fd, O_NONBLOCK)) {
        LOGD("turn_on_flags failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return NULL;
    }

    if (fd_type == SOCK_STREAM) {
        int cr = connect(fd, addr, addr_len);
        LOGD("connect(%s) result = %d, errno %d, err = %s", sockaddr_to_string(addr, NULL, 0), cr, errno,
             strerror(errno));
        if (cr == -1 && errno != EINPROGRESS) {
            if (ev != NULL && ev->err_cb) {
                ev->dns_ev = NULL;
                ev->err_cb(ev, MULTI_SOCKS_EV_ERROR | MULTI_SOCKS_EV_CONNECT, ctx);
                MAP_LOCK(base->event_map_mutex);
                ev = CSparseArray_get(base->event_map, fd);
                MAP_UNLOCK(base->event_map_mutex);
                multi_socks_epoll_server_event_free(ev);
            }

            LOGD("fd connect to %d failed: errno = %d, strerror = %s", fd, errno, strerror(errno));
            close(fd);
            return NULL;
        }
        LOGD("update_events");
    } else {
        struct sockaddr_in local_addr;
        size_t local_addr_len = sizeof(local_addr);
        bzero(&local_addr, local_addr_len);
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = htons(0);
        local_addr.sin_family = AF_INET;
        if (bind(fd, (struct sockaddr *) &local_addr, local_addr_len) == -1) {
            LOGD("bind udp failed: fd = %d", fd);
            close(fd);
            return NULL;
        }
    }

#ifdef __APPLE__
    struct kevent kev[1];
    EV_SET(&kev[0], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, (void *) (intptr_t) fd);
    if (kevent(base->e_fd, kev, 1, NULL, 0, NULL) == -1) {
        LOGD("kevent failed: errno = %d, errmsg: %s", errno, strerror(errno));
        close(fd);
        if (ev) {
            ev->fd = -1;
            multi_socks_epoll_server_event_free(ev);
        }
        return NULL;
    }
#elif __linux__ || __ANDROID__
    struct epoll_event event;
    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLET | EPOLLOUT; // read | ET(edge-triggered)
    if (epoll_ctl(base->e_fd, EPOLL_CTL_ADD, fd, &event) == -1) {
        if (ev != NULL) {
            if (ev->err_cb)
                ev->err_cb(ev, MULTI_SOCKS_EV_ERROR | MULTI_SOCKS_EV_CONNECT, ctx);
            multi_socks_epoll_server_event_free(ev);
        } else
            close(fd);
        LOGD("epoll_ctl failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return NULL;
    }
#endif

    if (ev == NULL)
        ev = MultiSocksEvent_new(base, fd, ctx);
    else if (ev->fd == -1)
        ev->fd = fd;
    ev->type = fd_type;
#ifdef EVENT_SSL
    if (ssl) {
        ev->ssl = SSL_new(base->ssl_ctx);
        ev->ssl_handshaking = true;
        if (!SSL_set_fd(ev->ssl, ev->fd)) {
            LOGE("SSL_set_fd failed: %s", ERR_error_string(ERR_get_error(), NULL));
        } else {
            SSL_set_connect_state(ev->ssl);
        }
    }
#endif

    if (fd_type == SOCK_DGRAM) {
        ev->addr = malloc(addr_len);
        memcpy(ev->addr, addr, addr_len);
        ev->addr_len = addr_len;
        ev->connect = 0;
        ev->udp_in_buf_map = c_hash_map_new();
        ev->udp_out_buf_map = c_hash_map_new();

        LOGD("udp address copy = %s", sockaddr_to_string(ev->addr, NULL, 0));
    }

    MAP_LOCK(base->event_map_mutex);
    CSparseArray_put(base->event_map, fd, ev);
    MAP_UNLOCK(base->event_map_mutex);
    LOGD("connect %s, fd = %d, ev = %p", sockaddr_to_string(addr, NULL, 0), ev->fd, ev);

    return ev;
}


static MultiSocksEvent *
multi_socks_epoll_server_connect_hostname_internal(MultiSocksBase *base,
                                                   int fd,
                                                   int type,
                                                   char *host,
                                                   int port,
                                                   int ssl,
                                                   void *ctx) {
    if (base == NULL || host == NULL) {
        LOGD("base = %p, host = %s", base, host);
        return NULL;
    }

    LOGD("host = %s, port = %d", host, port);
    char *fmt = NULL;
    int is_domain = 1;
    if (host[0] == '[') {
        is_domain = 0;
        fmt = "[%s]:%d";
    } else {
        int a, b, c, d;
        if (4 == sscanf(host, "%d.%d.%d.%d", &a, &b, &c, &d)) {
            if ((a >= 0 && a < 256) && (b >= 0 && b < 256) && (c >= 0 && c < 256) && (d >= 0 && d < 256)) {
                is_domain = 0;
                fmt = "%s:%d";
            }
        }
    }

    if (!is_domain) {
        struct sockaddr addr;
        socklen_t addr_len = sizeof(struct sockaddr);
        char *address = NULL;
        asprintf(&address, fmt, host, port);
        if (parse_address(address, &addr, &addr_len) != -1) {
            return multi_socks_epoll_server_connect_internal(base, NULL, fd, type, &addr, addr_len, ssl, ctx);
        }
    }

    int dns_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (dns_fd == -1) {
        LOGD("socket failed: errno = %d, strerror = %s", errno, strerror(errno));
        return NULL;
    }

    if (turn_on_flags(dns_fd, O_NONBLOCK)) {
        LOGD("turn_on_flags failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return NULL;
    }
    LOGD("update_events");

#ifdef __APPLE__
    update_events(base->e_fd, dns_fd, MULTI_SOCKS_READ_EVENT | MULTI_SOCKS_WRITE_EVENT, 0);
#elif __linux__ || __ANDROID__
    struct epoll_event event;
    event.data.fd = dns_fd;
    event.events = (uint32_t) EPOLLIN | (uint32_t) EPOLLET | (uint32_t) EPOLLOUT; // read | ET(edge-triggered)
    if (epoll_ctl(base->e_fd, EPOLL_CTL_ADD, dns_fd, &event) == -1) {
        LOGD("epoll_ctl failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return NULL;
    }
#endif
    LOGD("fd = %d", fd);
    MultiSocksEvent *ev = MultiSocksEvent_new(base, fd, ctx);
    ev->type = type;

    MultiSocksDNSEvent *dns_event = (MultiSocksDNSEvent *) (calloc(1, sizeof(MultiSocksDNSEvent)));
    dns_event->base = base;
    dns_event->event = ev;
    dns_event->dns_fd = dns_fd;
    dns_event->domain = strdup(host);
    dns_event->port = port;
#ifdef EVENT_SSL
    dns_event->ssl = ssl;
#endif
    ev->dns_ev = dns_event;

    if (fd == -1) {
        if (type == SOCK_STREAM) {
            ev->fd_in = socket(AF_INET, SOCK_STREAM, 0);
            ev->fd_in6 = socket(AF_INET6, SOCK_STREAM, 0);
        } else if (type == SOCK_DGRAM) {
            ev->fd_in = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            ev->fd_in6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        }
    }

    MAP_LOCK(base->dns_event_map_mutex);
    CSparseArray_put(base->dns_event_map, dns_fd, dns_event);
    MAP_UNLOCK(base->dns_event_map_mutex);
    LOGD("dns_fd = %d", dns_fd);

    return ev;
}

EVENT_PUBLIC_API
MultiSocksEvent *
multi_socks_epoll_server_connect_hostname(MultiSocksBase *base, int fd, char *host, int port, void *ctx) {
    return multi_socks_epoll_server_connect_hostname_internal(base, fd, SOCK_STREAM, host, port, false, ctx);
}

MultiSocksEvent *
multi_socks_epoll_server_ssl_connect_hostname(MultiSocksBase *base, int fd, char *host, int port, void *ctx) {
    return multi_socks_epoll_server_connect_hostname_internal(base, fd, SOCK_STREAM, host, port, true, ctx);
}

EVENT_PUBLIC_API
MultiSocksEvent *multi_socks_epoll_server_udp_hostname(MultiSocksBase *base, int fd, char *host, int port, void *ctx) {
    return multi_socks_epoll_server_connect_hostname_internal(base, fd, SOCK_DGRAM, host, port, false, ctx);
}

EVENT_PUBLIC_API
MultiSocksEvent *
multi_socks_epoll_server_connect(MultiSocksBase *base, int fd, struct sockaddr *addr, size_t addr_len, void *ctx) {
    return multi_socks_epoll_server_connect_internal(base, NULL, fd, SOCK_STREAM, addr, addr_len, 0, ctx);
}

MultiSocksEvent *
multi_socks_epoll_server_ssl_connect(MultiSocksBase *base, int fd, struct sockaddr *addr, size_t addr_len, void *ctx) {
    return multi_socks_epoll_server_connect_internal(base, NULL, fd, SOCK_STREAM, addr, addr_len, 1, ctx);
}

EVENT_PUBLIC_API
MultiSocksEvent *
multi_socks_epoll_server_udp(MultiSocksBase *base, int fd, struct sockaddr *addr, size_t addr_len, void *ctx) {
    return multi_socks_epoll_server_connect_internal(base, NULL, fd, SOCK_DGRAM, addr, addr_len, 0, ctx);
}