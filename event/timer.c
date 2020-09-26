//
// Created by haidy on 2020/7/15.
//

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#ifdef __APPLE__

#include <sys/event.h>

#elif __linux__ || __ANDROID__

#include <sys/epoll.h>
#include <sys/timerfd.h>

#endif

#include "timer.h"
#include "../log.h"
#include "c_linked_list.h"
#include "event.h"
#include "common.h"
#include "base.h"
#include "buffer.h"

#define MICROSECONDS_TO_NANOSECONDS 1000000
#define SECONDS_TO_MICROSECONDS 1000

static CLinkedList *timer_pool = NULL;

static int ms_timerfd_create() {
    int fd;
#ifdef __APPLE__
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
#elif __linux__ || __ANDROID__
    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
#endif
    return fd;
}


MultiSocksTimer *MultiSocksTimer_new(int fd) {
    char c = 0;
    if (fd == -1) {
        fd = ms_timerfd_create();
        c = 1;

        if (fd == -1) {
            LOGE("new MultiSocksTimer failed: errno = %d, strerror = %s", errno, strerror(errno));
            return NULL;
        }
    }

    MultiSocksTimer *timer;
    if (timer_pool == NULL)
        timer_pool = c_linked_list_new();

    timer = c_linked_list_remove_header(timer_pool);
    if (timer == NULL)
        timer = calloc(1, sizeof(MultiSocksTimer));

    timer->tfd = fd;
    timer->need_close_fd = c;
    return timer;
}

EVENT_PUBLIC_API
int multi_socks_epoll_server_stop_timer(MultiSocksTimer *timer) {
    if (timer == NULL)
        return -1;
    LOGD("timer = %p, tfd = %d", timer, timer->tfd);
    if (timer->base == NULL) {
        bzero(timer, sizeof(MultiSocksTimer));
        c_linked_list_add(timer_pool, timer);
        return -1;
    }
#ifdef __APPLE__
    struct kevent event;
    EV_SET(&event, timer->tfd, EVFILT_TIMER, 0, 0, 0, NULL);
    event.flags = (uint16_t) EV_DELETE | (uint16_t) EV_DISABLE;
    kevent(timer->base->e_fd, &event, 1, NULL, 0, NULL);
#elif __linux__ || __ANDROID__
    struct epoll_event event;
    event.data.fd = timer->tfd;
    event.events = EPOLLIN;
    epoll_ctl(timer->base->e_fd, EPOLL_CTL_DEL, timer->tfd, &event);
#endif
    if (timer->need_close_fd)
        close(timer->tfd);

    bzero(timer, sizeof(MultiSocksTimer));
    c_linked_list_add(timer_pool, timer);

    return 0;
}

MultiSocksTimer *
multi_socks_epoll_server_event_set_timer_internal(MultiSocksEvent *ev, int64_t interval, int oneshot,
                                                  multi_socks_epoll_server_timer_cb cb, void *ctx) {
    LOGD("ev = %p, interval = %ld, oneshot = %d, cb = %p, ctx = %p", ev, (long) interval, oneshot, cb, ctx);
    if (ev == NULL)
        return NULL;

    if (ev->fd == -1) {
        LOGE("event fd = -1, set timer failed.");
        return NULL;
    }

    if (interval < 0) {
        LOGE("interval MUST > 0");
        return NULL;
    }

    if (interval == 0)
        return NULL;

    if (ev->base == NULL) {
        LOGI("ev base is null");
        return NULL;
    }

#ifdef __APPLE__
    int tfd = ms_timerfd_create();

    if (tfd == -1) {
        LOGE("ms_timerfd_create failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return NULL;
    }

    struct kevent event;
    MultiSocksTimer *timer = MultiSocksTimer_new(tfd);
    EV_SET(&event, tfd, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0, interval, (void *) (intptr_t) tfd);
    kevent(ev->base->e_fd, &event, 1, NULL, 0, NULL);
#elif __linux__ || __ANDROID__
    int tfd = ms_timerfd_create();
    if (tfd == -1) {
        LOGE("ms_timerfd_create failed: errno = %d, errmsg: %s", errno, strerror(errno));
        return NULL;
    }

    struct itimerspec its;
    bzero(&its, sizeof(its));
    its.it_value.tv_sec = interval / SECONDS_TO_MICROSECONDS;
    its.it_value.tv_nsec = (interval % SECONDS_TO_MICROSECONDS) * MICROSECONDS_TO_NANOSECONDS;
    if (!oneshot) {
        its.it_interval.tv_sec = interval / SECONDS_TO_MICROSECONDS;
        its.it_interval.tv_nsec = (interval % SECONDS_TO_MICROSECONDS) * MICROSECONDS_TO_NANOSECONDS;
    }
    if (timerfd_settime(tfd, 0, &its, NULL) == -1) {
        LOGE("ms_timerfd_create failed: errno = %d, errmsg: %s", errno, strerror(errno));
        close(tfd);
        return NULL;
    }

    struct epoll_event event;
    bzero(&event, sizeof(event));
    event.data.fd = tfd;
    event.events = EPOLLIN;
    if (epoll_ctl(ev->base->e_fd, EPOLL_CTL_ADD, tfd, &event) == -1) {
        LOGE("epoll_ctl failed: errno = %d, errmsg: %s", errno, strerror(errno));
        close(tfd);
        return NULL;
    }
    MultiSocksTimer *timer = MultiSocksTimer_new(tfd);
    timer->need_close_fd = 1;
#endif
    timer->base = ev->base;
    timer->cb = cb;
    timer->ctx = ctx;
    timer->oneshot = oneshot;
    timer->ev_fd = ev->fd;
    LOGD("tfd = %d, fd = %d", timer->tfd, ev->fd);

    MAP_LOCK(ev->base->timer_map_mutex);
    CSparseArray_put(ev->base->timer_map, tfd, timer);
    MAP_UNLOCK(ev->base->timer_map_mutex);

    return timer;
}

EVENT_PUBLIC_API
MultiSocksTimer *
multi_socks_epoll_server_event_set_timer(MultiSocksEvent *ev, int64_t interval, multi_socks_epoll_server_timer_cb cb,
                                         void *ctx) {
    if (ev->timer != NULL && !ev->timer->oneshot) {
        LOGE("ev timer has been set, you should cancel old one first");
        return NULL;
    }
    ev->timer = multi_socks_epoll_server_event_set_timer_internal(ev, interval, 0, cb, ctx);
    return ev->timer;
}

EVENT_PUBLIC_API
MultiSocksTimer *multi_socks_epoll_server_event_set_timer_oneshot(MultiSocksEvent *ev, int64_t interval,
                                                                  multi_socks_epoll_server_timer_cb cb, void *ctx) {
    if (ev->timer != NULL && !ev->timer->oneshot) {
        LOGE("ev timer has been set, you should cancel old one first");
        return NULL;
    }
    ev->timer = multi_socks_epoll_server_event_set_timer_internal(ev, interval, 1, cb, ctx);
    return ev->timer;
}

void read_timeout_internal(MultiSocksTimer *timer, void *ctx) {
    LOGD("timer = %p, event fd = %d", timer, timer->ev_fd);

    MAP_LOCK(timer->base->event_map_mutex);
    MultiSocksEvent *ev = CSparseArray_get(timer->base->event_map, timer->ev_fd);
    MAP_UNLOCK(timer->base->event_map_mutex);
    if (ev == NULL) {
        multi_socks_epoll_server_stop_timer(timer);
        return;
    }
    event_self_close(ev->fd, MULTI_SOCKS_EV_READ | MULTI_SOCKS_EV_TIME_OUT, ev);
}