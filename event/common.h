//
// Created by haidy on 2020/7/15.
//

#ifndef SOCKS_COMMON_H
#define SOCKS_COMMON_H

#define EVENT_PUBLIC_API __attribute__((visibility("default")))
#define MULTI_SOCKS_DEFAULT_RECYCLE_BUF_SIZE 4096
#define FD_NUM 2
#define MULTI_SOCKS_READ_EVENT (u_char)1
#define MULTI_SOCKS_WRITE_EVENT (u_char)2
#define MULTI_SOCKS_MAX_EVENTS 16
#define MULTI_SOCKS_BUF_SIZE 1024

#define set_write_enable(event) event->ev |= MULTI_SOCKS_WRITE_EVENT
#define set_read_enable(event) event->ev |= MULTI_SOCKS_READ_EVENT

#define set_write_disable(event) event->ev &= (u_char)~MULTI_SOCKS_WRITE_EVENT
#define set_read_disable(event) event->ev &= (u_char)~MULTI_SOCKS_READ_EVENT

#define write_enable(event) ((event->ev & MULTI_SOCKS_WRITE_EVENT) != 0)
#define read_enable(event) (event->ev & MULTI_SOCKS_READ_EVENT) != 0

#ifdef __APPLE__

void update_events(int kq, int fd, int events, int modify);

#endif

#endif //SOCKS_COMMON_H
