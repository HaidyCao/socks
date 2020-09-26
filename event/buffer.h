//
// Created by haidy on 2020/7/14.
//

#ifndef SOCKS_BUFFER_H
#define SOCKS_BUFFER_H

#include <stdlib.h>

#include <pthread.h>

#include "multi_socks_epoll_server.h"
#include "c_linked_list.h"

#define MS_BUFSIZE 4096

typedef struct {
    size_t len;
    size_t pos;
    char data[MS_BUFSIZE];
} EventBuffer;

EventBuffer *event_get_buffer_from_pool();

void EventBuffer_release(EventBuffer *buffer);

struct multi_socks_epoll_server_buffer {
    MultiSocksEvent *event;
    size_t length;

    CLinkedList *data_list;

#ifndef EVENT_SINGLE_THREAD
    pthread_mutex_t mutex;
#endif
};

void MultiSocksBuffer_init(MultiSocksBuffer *buffer, MultiSocksEvent *event);

void MultiSocksBuffer_free_internal(MultiSocksBuffer *buf);

#ifdef EVENT_SINGLE_THREAD

#define MultiSocksBuffer_lock(buf)

#define MultiSocksBuffer_unlock(buf)

#define MSB_LOCK(buf, block)    \
    block                       \

#else

#define MultiSocksBuffer_lock(buf) pthread_mutex_lock(&buf->mutex)

#define MultiSocksBuffer_unlock(buf) pthread_mutex_unlock(&buf->mutex)

#define MSB_LOCK(buf, block) MultiSocksBuffer_lock(buf);    \
    block                                                   \
    MultiSocksBuffer_unlock(buf);

#endif


int multi_socks_epoll_server_buffer_write_internal(MultiSocksBuffer *buf, char *data, size_t len);

#endif //SOCKS_BUFFER_H
