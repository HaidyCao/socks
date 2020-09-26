//
// Created by haidy on 2020/7/14.
//
#include <string.h>

#include "buffer.h"
#include "../log.h"
#include "common.h"
#include "event.h"
#include "lib/c_array_list.h"

static CArrayList *buffer_pool = NULL;

EVENT_PUBLIC_API
MultiSocksBuffer *MultiSocksBuffer_new() {
    MultiSocksBuffer *buffer = malloc(sizeof(MultiSocksBuffer));
    MultiSocksBuffer_init(buffer, NULL);
    return buffer;
}

EVENT_PUBLIC_API
void MultiSocksBuffer_free(MultiSocksBuffer *buffer) {
    MultiSocksBuffer_free_internal(buffer);
    free(buffer);
}

EventBuffer *event_get_buffer_from_pool() {
    if (buffer_pool == NULL)
        buffer_pool = CArrayList_new();

    EventBuffer *buffer = CArrayList_remove_last(buffer_pool);
    if (buffer == NULL) {
        buffer = malloc(sizeof(EventBuffer));
    }
    buffer->len = 0;
    buffer->pos = 0;
    return buffer;
}

void EventBuffer_release(EventBuffer *buffer) {
    if (buffer_pool == NULL)
        buffer_pool = CArrayList_new();

    CArrayList_add(buffer_pool, buffer);
}

void MultiSocksBuffer_init(MultiSocksBuffer *buffer, MultiSocksEvent *event) {
    bzero(buffer, sizeof(MultiSocksBuffer));
    buffer->length = 0;
    buffer->data_list = c_linked_list_new();
    buffer->event = event;

    pthread_mutex_init(&buffer->mutex, NULL);
}

void MultiSocksBuffer_free_internal(MultiSocksBuffer *buf) {
    if (buf == NULL)
        return;

    MSB_LOCK(buf, {
        buf->event = NULL;

        EventBuffer *mb;
        while ((mb = c_linked_list_remove_header(buf->data_list)) != NULL) {
            EventBuffer_release(mb);
        }
        c_linked_list_free(buf->data_list);
        buf->data_list = NULL;
    })

    pthread_mutex_destroy(&buf->mutex);
}

static ssize_t MultiSocksBuffer_remove_data(MultiSocksBuffer *buf, char **data, size_t r_len) {
    if (buf == NULL) return -1;

    int result = 0;
    MSB_LOCK(buf, {
        if (buf->length < r_len || r_len == 0) {
            result = -1;
        } else {
            char *ret = (data != NULL) ? malloc(r_len) : NULL;
            size_t removed_size = 0;
            size_t left_size = r_len;
            EventBuffer *buffer;
            while ((buffer = c_linked_list_get_header(buf->data_list))) {
                if (buffer->len > left_size) {
                    if (data != NULL) memcpy(ret + removed_size, buffer->data + buffer->pos, left_size);
                    buffer->pos += left_size;
                    buffer->len -= left_size;
                    buf->length -= left_size;
                    break;
                }

                if (data != NULL) memcpy(ret + removed_size, buffer->data + buffer->pos, buffer->len);
                removed_size += buffer->len;
                left_size -= buffer->len;
                buf->length -= buffer->len;

                c_linked_list_remove_header(buf->data_list);
                EventBuffer_release(buffer);
            }

            if (data != NULL) *data = ret;
            result = r_len;
        }
    })

    return result;
}

EVENT_PUBLIC_API
size_t multi_socks_epoll_server_buffer_get_length(MultiSocksBuffer *buf) {
    if (buf == NULL)
        return 0;
    size_t len;
    MSB_LOCK(buf, {
        len = buf->length;
    })
    return len;
}

EVENT_PUBLIC_API
ssize_t multi_socks_epoll_server_buffer_copyout(MultiSocksBuffer *buf, char *data, size_t len) {
    LOGD("len = %zu", len);
    if (buf == NULL)
        return -1;
    if (data == NULL) {
        LOGD("data is null");
        return -1;
    }

    if (len == 0) {
        LOGD("len MUST > 0");
        return -1;
    }

    MultiSocksBuffer_lock(buf);
    if (buf->length == 0) {
        LOGD("buf is empty");
        MultiSocksBuffer_unlock(buf);
        return 0;
    }

    size_t left_size = len;
    size_t pos = 0;

    void *it = c_linked_list_iterator(buf->data_list);
    EventBuffer *mb;
    while (it != NULL) {
        mb = c_linked_list_iterator_get_value(it);
        if (mb == NULL || mb->len == 0) {
            it = c_linked_list_iterator_next(it);
            continue;
        }
        if (mb->len >= left_size) {
            memcpy(data + pos, mb->data + mb->pos, left_size);
            left_size = 0;
            break;
        }
        memcpy(data + pos, mb->data + mb->pos, mb->len);
        left_size -= mb->len;
        pos += mb->len;

        it = c_linked_list_iterator_next(it);
    }
    MultiSocksBuffer_unlock(buf);

    LOGD("copyout len = %zu", len - left_size);
    return len - left_size;
}

EVENT_PUBLIC_API
ssize_t multi_socks_epoll_server_buffer_move_out(MultiSocksBuffer *buf, char **data, size_t *len) {
    if (data == NULL || len == NULL) return -1;

    ssize_t result = MultiSocksBuffer_remove_data(buf, data, buf->length);
    if (result > 0) *len = result;
    return result;
}

EVENT_PUBLIC_API
int multi_socks_epoll_server_buffer_remove(MultiSocksBuffer *buf, size_t len) {
    return MultiSocksBuffer_remove_data(buf, NULL, len);
}

int multi_socks_epoll_server_buffer_write_internal(MultiSocksBuffer *buf, char *data, size_t len) {
    LOGD("buffer(%p) write len = %zu", buf, len);
    if (buf == NULL)
        return -1;

    if (len == 0)
        return 0;

    size_t left_size = len;
    size_t pos = 0;

    CLinkedList *list = c_linked_list_new();
    size_t _len = 0;

    EventBuffer *mb = event_get_buffer_from_pool();
    c_linked_list_add(list, mb);
    do {
        size_t footer_left = sizeof(mb->data) - mb->pos - mb->len;
        size_t cpy_len = left_size > footer_left ? footer_left : left_size;

        memcpy(mb->data + mb->pos + mb->len, data + pos, cpy_len);
        mb->len += cpy_len;

        left_size -= cpy_len;
        pos += cpy_len;
        _len += cpy_len;

        if (left_size == 0)
            break;
        mb = event_get_buffer_from_pool();
        c_linked_list_add(list, mb);
    } while (1);

    MSB_LOCK(buf, {
        c_linked_list_merge(buf->data_list, list);
        buf->length += _len;
    })

    c_linked_list_free(list);
    LOGD("pos = %zu, buf->len = %zu", pos, buf->length);
    return 0;
}