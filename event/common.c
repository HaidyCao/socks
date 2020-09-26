//
// Created by haidy on 2020/7/15.
//
#include <errno.h>

#include "common.h"
#include "multi_socks_epoll_server.h"
#include "log.h"

#ifdef __APPLE__

#include <sys/event.h>

void update_events(int kq, int fd, int events, int mod) {
    struct kevent ev[FD_NUM];
    int n = 0;
    if (events & MULTI_SOCKS_READ_EVENT) {
        EV_SET(&ev[n++], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void *) (intptr_t) fd);
    } else if (mod) {
        EV_SET(&ev[n++], fd, EVFILT_READ, EV_DELETE, 0, 0, (void *) (intptr_t) fd);
    }
    if (events & MULTI_SOCKS_WRITE_EVENT) {
        EV_SET(&ev[n++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, (void *) (intptr_t) fd);
    } else if (mod) {
        EV_SET(&ev[n++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, (void *) (intptr_t) fd);
    }
    LOGD("%s fd %d events read %d write %d\n",
         mod ? "mod" : "add", fd, events & MULTI_SOCKS_READ_EVENT, events & MULTI_SOCKS_WRITE_EVENT);
    int r = kevent(kq, ev, n, NULL, 0, NULL);
    if (r == -1) {
        LOGD("kevent failed: errno = %d, errmsg: %s", errno, strerror(errno));
    }
}

#elif __linux__ || __ANDROID__
// TODO
#endif