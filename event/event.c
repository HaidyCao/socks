//
// Created by haidy on 2020/7/15.
//
#include <errno.h>
#include <unistd.h>

#ifdef __APPLE__

#include <sys/event.h>

#elif __linux__ || __ANDROID__

#include <sys/epoll.h>
#include <sys/timerfd.h>

#endif

#include "event.h"
#include "common.h"
#include "../log.h"
#include "timer.h"
#include "clib.h"
#include "base.h"

MultiSocksEvent *MultiSocksEvent_new(MultiSocksBase *base, int fd, void *ctx) {
    MultiSocksEvent *ev = calloc(1, sizeof(MultiSocksEvent));
    ev->base = base;
    MultiSocksBuffer_init(&ev->in_buffer, ev);
    MultiSocksBuffer_init(&ev->out_buffer, ev);
    ev->fd = fd;
    ev->ctx = ctx;
    ev->ev = MULTI_SOCKS_WRITE_EVENT | MULTI_SOCKS_READ_EVENT;
    ev->connect = 1;
    ev->timer = NULL;
    ev->timeout = NULL;

    return ev;
}


EVENT_PUBLIC_API
void *multi_socks_epoll_server_event_get_ctx(MultiSocksEvent *ev) {
    if (ev == NULL) {
        return NULL;
    }
    return ev->ctx;
}

EVENT_PUBLIC_API
int multi_socks_epoll_server_event_get_fd(MultiSocksEvent *ev) {
    if (ev == NULL) {
        return -1;
    }

    return ev->fd;
}

EVENT_PUBLIC_API
MultiSocksBase *multi_socks_epoll_server_event_get_base(MultiSocksEvent *ev) {
    if (ev)
        return ev->base;
    return NULL;
}

void remove_event(int e_fd, int fd) {
    LOGD("remove_event");
#ifdef __APPLE__
    // update_events(e_fd, fd, 0, 1);
#elif __linux__ || __ANDROID__
    if (epoll_ctl(e_fd, EPOLL_CTL_DEL, fd, NULL) == -1) {
        LOGD("epoll_ctl failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return;
    }
#endif
}

void event_self_close(int fd, int what, MultiSocksEvent *event) {
    LOGD("event_self_close");
    error_cb cb = event->err_cb;
    void *ctx = event->ctx;
    // close will call
    multi_socks_epoll_server_event_free(event);
    if (cb)
        cb(NULL, MULTI_SOCKS_EV_EOF, ctx);
}

EVENT_PUBLIC_API
MultiSocksTimer *
multi_socks_epoll_server_event_set_timeout(MultiSocksEvent *ev, int64_t read_timeout, int64_t write_timeout) {
    LOGD("ev = %p, ev->fd = %d, read_timeout = %ld, write_timeout = %ld", ev, ev->fd, (long) read_timeout,
         (long) write_timeout);
    if (ev == NULL)
        return NULL;

    if (ev->fd == -1) {
        ev->read_timeout = read_timeout;
        ev->write_timeout = write_timeout;
        return NULL;
    }

    if (read_timeout < 0 || write_timeout < 0)
        return NULL;

    ev->read_timeout = read_timeout;
    ev->write_timeout = write_timeout;
    time_t now = get_current_millisecond();
    ev->last_read_time = ev->last_write_time = now;

    int64_t min_timeout = read_timeout > write_timeout ? write_timeout : read_timeout;
    ev->timeout = multi_socks_epoll_server_event_set_timer_internal(ev, min_timeout, 1, read_timeout_internal, NULL);
    return ev->timeout;
}

void multi_socks_epoll_server_dns_event_free(MultiSocksDNSEvent *event) {
    LOGD("dns event free: fd = %d, domain = %s", event->dns_fd, event->domain);
    MultiSocksBase *base = event->base;
    if (base != NULL && event->dns_fd != -1) {
        LOGD("remove_event");
#ifdef __APPLE__
        // struct kevent ev[1];
        // EV_SET(&ev[0], event->dns_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        // if (kevent(event->base->e_fd, ev, 1, NULL, 0, NULL) == -1)
        // {
        //     LOGD("kevent failed: errno = %d, errmsg: %s", errno, strerror(errno));
        // }
#elif __linux__ || __ANDROID__
        remove_event(event->base->e_fd, event->dns_fd);
#endif
        close(event->dns_fd);
        MAP_LOCK(base->dns_event_map_mutex);
        void *p = CSparseArray_remove(base->dns_event_map, event->dns_fd);
        MAP_UNLOCK(base->dns_event_map_mutex);
        LOGD("dns_event = %p, remove dns event result = %p", event, p);
    }
    int dns_fd = event->dns_fd;
    if (event->event && event->event->err_cb) {
        int fd = event->event->fd;
        event->event->err_cb(event->event, MULTI_SOCKS_EV_ERROR | MULTI_SOCKS_EV_CONNECT, event->event->ctx);

        MAP_LOCK(base->event_map_mutex);
        event->event = CSparseArray_get(base->event_map, fd);
        MAP_LOCK(base->event_map_mutex);
        multi_socks_epoll_server_event_free(event->event);
        event->event = NULL;
    }
    MAP_LOCK(base->dns_event_map_mutex);
    event = CSparseArray_get(base->dns_event_map, dns_fd);
    MAP_LOCK(base->dns_event_map_mutex);

    if (event == NULL) return;

    free(event->domain);
    event->domain = NULL;
    free(event);
}

static void hash_map_buffer_free(void *v) {
    MultiSocksBuffer *buffer = v;
    MultiSocksBuffer_free(buffer);
}

static void hash_map_out_buffer_free(void *v) {
    MultiSocksBuffer *buffer = v;
    if (buffer->length > 0) {

    }
    MultiSocksBuffer_free(buffer);
}

EVENT_PUBLIC_API
void multi_socks_epoll_server_event_free(MultiSocksEvent *ev) {
    if (ev == NULL)
        return;
    if (ev->fd > 0) {
        LOGD("remove_event, fd = %d", ev->fd);
        if (ev->base)
            remove_event(ev->base->e_fd, ev->fd);

        close(ev->fd);

        if (ev->base) {
            LOGD("remove_event from base->event_map fd = %d", ev->fd);
            MAP_LOCK(ev->base->event_map_mutex);
            void *v = CSparseArray_remove(ev->base->event_map, ev->fd);
            MAP_UNLOCK(ev->base->event_map_mutex);

            if (v != ev) {
                LOGE("remove result (%p) != ev (%p)", v, ev);
            }
        }
    }
    MultiSocksBuffer_free_internal(&ev->in_buffer);
    MultiSocksBuffer_free_internal(&ev->out_buffer);

    if (ev->timer) {
        LOGD("remove timer from map: tfd = %d", ev->timer->tfd);
        MAP_LOCK(ev->base->timer_map_mutex);
        CSparseArray_remove(ev->base->timer_map, ev->timer->tfd);
        MAP_UNLOCK(ev->base->timer_map_mutex);
        multi_socks_epoll_server_stop_timer(ev->timer);
        ev->timer = NULL;
    }

    if (ev->timeout) {
        LOGD("remove timer from map: tfd = %d", ev->timeout->tfd);
        MAP_LOCK(ev->base->timer_map_mutex);
        CSparseArray_remove(ev->base->timer_map, ev->timeout->tfd);
        MAP_UNLOCK(ev->base->timer_map_mutex);
        multi_socks_epoll_server_stop_timer(ev->timeout);
        ev->timeout = NULL;
    }
    ev->ctx = NULL;
    free(ev->addr);
    ev->addr = NULL;

    if (ev->dns_ev) {
        ev->dns_ev->event = NULL;
        multi_socks_epoll_server_dns_event_free(ev->dns_ev);
    }

    if (ev->udp_in_buf_map) {
        c_hash_map_set_free_cb(ev->udp_in_buf_map, hash_map_buffer_free);
        c_hash_map_set_free_cb(ev->udp_out_buf_map, hash_map_out_buffer_free);
        c_hash_map_free(ev->udp_in_buf_map);
        c_hash_map_free(ev->udp_out_buf_map);
        ev->udp_in_buf_map = NULL;
        ev->udp_out_buf_map = NULL;
    }

    free(ev);
}


EVENT_PUBLIC_API
int multi_socks_ev_udp_setcb(MultiSocksEvent *event, udp_event_cb read_cb, udp_event_cb write_cb, error_cb event_cb,
                             void *ctx) {
    if (event == NULL)
        return -1;

    event->udp_read_cb = read_cb;
    event->udp_write_cb = write_cb;
    event->err_cb = event_cb;
    event->ctx = ctx;

    if (c_hash_map_get_count(event->udp_in_buf_map) > 0 && read_cb) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        C_HASH_MAP_FOR(event->udp_in_buf_map, {
            if (parse_address(k, (struct sockaddr *) &addr, &addr_len) == -1) {
                LOGD("parse address failed");
                continue;
            }

            MultiSocksBuffer *buffer = v;
            if (multi_socks_epoll_server_buffer_get_length(buffer) == 0) {
                continue;
            }

            read_cb(event, buffer, (struct sockaddr *) &addr, addr_len, ctx);
        })
    }

    if (c_hash_map_get_count(event->udp_out_buf_map) > 0 && write_cb) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        C_HASH_MAP_FOR(event->udp_in_buf_map, {
            if (parse_address(k, (struct sockaddr *) &addr, &addr_len) == -1) {
                LOGD("parse address failed");
                continue;
            }

            MultiSocksBuffer *buffer = v;
            if (multi_socks_epoll_server_buffer_get_length(buffer) == 0) {
                continue;
            }

            write_cb(event, buffer, (struct sockaddr *) &addr, addr_len, ctx);
        })
    }

    return 0;
}


EVENT_PUBLIC_API
MultiSocksBuffer *multi_socks_ev_get_input(MultiSocksEvent *event) {
    if (event == NULL)
        return NULL;
    return &event->in_buffer;
}


EVENT_PUBLIC_API
MultiSocksBuffer *multi_socks_ev_get_output(MultiSocksEvent *event) {
    if (event == NULL)
        return NULL;
    return &event->out_buffer;
}

EVENT_PUBLIC_API
MultiSocksBuffer *multi_socks_ev_udp_get_output(MultiSocksEvent *event, struct sockaddr *addr, socklen_t addr_len) {
    if (event == NULL) {
        LOGE("event is NULL");
        return NULL;
    }

    if (event->udp_out_buf_map == NULL) {
        LOGE("udp_out_buf_map is NULL");
        return NULL;
    }

    char *address = sockaddr_to_string(addr, NULL, 0);
    MultiSocksBuffer *buffer = c_hash_map_get(event->udp_out_buf_map, address);
    if (buffer == NULL) {
        buffer = MultiSocksBuffer_new();
        buffer->event = event;
        c_hash_map_put(event->udp_out_buf_map, address, buffer);
    }

    return buffer;
}

static uint32_t get_events(MultiSocksEvent *event) {
#ifdef __APPLE__
    return event->ev;
#elif __linux__ || __ANDROID__
    uint events = 0;
    if (write_enable(event)) {
        events |= EPOLLOUT;
    }

    if (read_enable(event)) {
        events |= EPOLLIN;
    }
    return events;
#endif
}

void multi_socks_epoll_server_event_disable_read(MultiSocksEvent *ev) {
    if (ev == NULL || ev->base == NULL)
        return;
    set_read_disable(ev);
#ifdef __APPLE__
    update_events(ev->base->e_fd, ev->fd, get_events(ev), 1);
#elif __linux__ || __ANDROID__
    struct epoll_event event;
    event.data.fd = ev->fd;
    event.events = get_events(ev) | EPOLLET; // read | ET(edge-triggered)
    if (epoll_ctl(ev->base->e_fd, EPOLL_CTL_MOD, ev->fd, &event) == -1) {
        LOGE("epoll_ctl failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return;
    }
#endif
}

void multi_socks_epoll_server_event_enable_read(MultiSocksEvent *ev) {
    if (ev == NULL || ev->base == NULL)
        return;
    set_read_enable(ev);
#ifdef __APPLE__
    update_events(ev->base->e_fd, ev->fd, get_events(ev), 1);
#elif __linux__ || __ANDROID__
    struct epoll_event event;
    event.data.fd = ev->fd;
    event.events = get_events(ev) | EPOLLET; // read | ET(edge-triggered)
    if (epoll_ctl(ev->base->e_fd, EPOLL_CTL_MOD, ev->fd, &event) == -1) {
        LOGD("epoll_ctl failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return;
    }
#endif
}

void multi_socks_epoll_server_event_enable_write(MultiSocksEvent *ev) {
    if (ev == NULL || ev->base == NULL)
        return;
    set_write_enable(ev);
#ifdef __APPLE__
    update_events(ev->base->e_fd, ev->fd, get_events(ev), 1);
#elif __linux__ || __ANDROID__
    struct epoll_event event;
    event.data.fd = ev->fd;
    event.events = get_events(ev) | EPOLLET; // read | ET(edge-triggered)
    if (epoll_ctl(ev->base->e_fd, EPOLL_CTL_MOD, ev->fd, &event) == -1) {
        LOGD("epoll_ctl failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return;
    }
#endif
}