
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "event2/buffer.h"
#include "event2/event.h"
#include "event2/bufferevent.h"
#include "event2/listener.h"

void event_cb(struct bufferevent *bev, short what, void *ctx)
{
    perror("event_cb");
    printf("what = %x\n", what);

    if (what == (BEV_EVENT_TIMEOUT | BEV_EVENT_WRITING))
    {
        printf("timeout\n");
        bufferevent_free(bev);
    }
    else if (what & BEV_EVENT_CONNECTED)
    {
        printf("connected\n");
        bufferevent_free(bev);
    }
    
}

void connect_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *ctx)
{
    perror("connect_cb");
    struct event_base *base = (struct event_base *)ctx;
    struct bufferevent *be = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(443);
    server.sin_addr.s_addr = inet_addr("61.135.169.121");

    struct bufferevent *remote = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    bufferevent_socket_connect(remote, (struct sockaddr *)&server, sizeof(server));
    bufferevent_setcb(remote, NULL, NULL, event_cb, base);
    // bufferevent_enable(remote, EV_WRITE);
    struct timeval *tv = (struct timeval *)malloc(sizeof(struct timeval));
    tv->tv_sec = 10;
    tv->tv_usec = 0;
    bufferevent_set_timeouts(remote, tv, tv);

    // bufferevent_setcb(evClient, NULL, NULL, event_cb, evClient);
    // bufferevent_enable(evClient, EV_READ);
    // struct timeval tv = {1, 0};
    // bufferevent_set_timeouts(evClient, &tv, NULL);

    bufferevent_free(be);
}

int main(int argc, char **argv)
{
    struct event_base *base = event_base_new();
    // int fd = socket(AF_INET, SOCK_STREAM, 0);
    // struct bufferevent *evClient = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(1080);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    // bufferevent_socket_connect(evClient, (struct sockaddr *)&server, sizeof(server));

    // bufferevent_setcb(evClient, NULL, NULL, event_cb, evClient);
    // bufferevent_enable(evClient, EV_READ);
    // struct timeval tv = {1, 0};
    // bufferevent_set_timeouts(evClient, &tv, NULL);
    struct evconnlistener *listener = evconnlistener_new_bind(base, connect_cb, base, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE, -1, (struct sockaddr *)&server, sizeof(server));

    event_base_loop(base, 0);

    perror("event_base_dispatch");
    return 0;
}