#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "event2/util.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/event.h"
#include "event2/listener.h"
#include "event2/dns.h"
#include "event2/event-config.h"
#include "event2/bufferevent_ssl.h"
#include "openssl/ssl.h"
#include "openssl/rand.h"
#include "openssl/err.h"

#include "local_dec_server.h"
#include "log.h"
#include "clib.h"

#define MAX_OUTPUT (512 * 1024)

#define TYPE_CLIENT 0
#define TYPE_REMOTE 1

#define TYPE_to_string(type) type == TYPE_CLIENT ? "Client" : (type == TYPE_REMOTE ? "Remote" : "Unknown")

#define STATUS_CONNECTING 0
#define STATUS_OK 1
#define STATUS_DISCONNECT 2

const struct timeval connect_timeout = {30, 0};

SSL_CTX *ssl_ctx;

static struct event_base *base;
static struct evdns_base *dns_base;

static char *remote_host;
static int remote_port;

struct buffer_context
{
    int type;
    struct bufferevent *bev;
    int status;
    struct buffer_context *partner;
};

typedef struct buffer_context BUF_ctx;
typedef struct evbuffer EV_BUF;

static void write_cb(struct bufferevent *bev, void *ctx);
static void event_cb(struct bufferevent *bev, short what, void *ctx);
static void read_cb(struct bufferevent *bev, void *ctx);

static void free_buffer_context(BUF_ctx *context)
{
    if (context == NULL)
    {
        return;
    }
    bufferevent_free(context->bev);
    context->bev = NULL;
    if (context->partner != NULL)
        context->partner->partner = NULL;

    free(context);
}

static void close_write_cb(struct bufferevent *bev, void *ctx)
{
    BUF_ctx *context = (BUF_ctx *)ctx;
    struct evbuffer *out = bufferevent_get_output(context->bev);
    if (evbuffer_get_length(out) == 0)
        free_buffer_context(context);
}

static void drained_write_cb(struct bufferevent *bev, void *ctx)
{
    BUF_ctx *context = (BUF_ctx *)ctx;
    bufferevent_setcb(bev, read_cb, write_cb, event_cb, ctx);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    if (context->partner != NULL && context->partner->bev != NULL)
        bufferevent_enable(context->partner->bev, EV_READ);
}

static void read_cb(struct bufferevent *bev, void *ctx)
{
    BUF_ctx *context = (BUF_ctx *)ctx;
    EV_BUF *in = bufferevent_get_input(bev);
    EV_BUF *out = bufferevent_get_output(context->partner->bev);

    evbuffer_add_buffer(out, in);
    if (evbuffer_get_length(out) > MAX_OUTPUT)
    {
        bufferevent_setcb(context->partner->bev, read_cb, drained_write_cb, event_cb, context->partner);
        bufferevent_setwatermark(context->partner->bev, EV_WRITE, MAX_OUTPUT / 2, MAX_OUTPUT);
        bufferevent_disable(bev, EV_READ);
    }
}

static void write_cb(struct bufferevent *bev, void *ctx)
{
}

static void event_cb(struct bufferevent *bev, short what, void *ctx)
{
    BUF_ctx *context = (BUF_ctx *)ctx;
    if (what & (BEV_EVENT_READING | BEV_EVENT_WRITING | BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT))
    {
        LOGI("type = %s, fd = %d closed", TYPE_to_string(context->type), bufferevent_getfd(context->bev));
        BUF_ctx *partner = context->partner;
        if (partner == NULL)
        {
            free_buffer_context(context);
            return;
        }

        struct evbuffer *out = bufferevent_get_output(partner->bev);
        if (out == NULL || evbuffer_get_length(out) == 0)
        {
            free_buffer_context(context);
            free_buffer_context(partner);
            return;
        }

        partner->partner = NULL;
        bufferevent_setcb(partner->bev, NULL, close_write_cb, event_cb, partner);
        bufferevent_disable(partner->bev, EV_READ);
        free_buffer_context(context);
    }
}

static void connect_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *ctx)
{
    LOGI("new connect: fd = %d, address = %s", fd, sockaddr_to_string(addr, NULL, 0));
    BUF_ctx *context = (BUF_ctx *)malloc(sizeof(BUF_ctx));
    context->type = TYPE_CLIENT;
    context->bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    if (context->bev == NULL)
    {
        free_buffer_context(context);
        return;
    }

    BUF_ctx *remote = (BUF_ctx *)malloc(sizeof(BUF_ctx));
    remote->type = TYPE_REMOTE;
    remote->bev = bufferevent_openssl_socket_new(base, -1, SSL_new(ssl_ctx), BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    if (remote->bev == NULL)
    {
        free_buffer_context(context);
        free_buffer_context(remote);
        return;
    }
    if (bufferevent_socket_connect_hostname(remote->bev, dns_base, AF_UNSPEC, remote_host, remote_port) == -1)
    {
        LOGI("connect remote (%s %d) failed", remote_host, remote_port);
        free_buffer_context(context);
        free_buffer_context(remote);
        return;
    }
    context->partner = remote;
    remote->partner = context;

    bufferevent_setcb(context->bev, read_cb, NULL, event_cb, context);
    bufferevent_setcb(remote->bev, read_cb, NULL, event_cb, remote);

    bufferevent_enable(context->bev, EV_READ | EV_WRITE);
    bufferevent_enable(remote->bev, EV_READ | EV_WRITE);

    bufferevent_set_timeouts(context->bev, &connect_timeout, &connect_timeout);
    bufferevent_set_timeouts(remote->bev, &connect_timeout, &connect_timeout);
}

int set_remote_server(const char *host, const char *port)
{
    if (host == NULL)
    {
        LOGE("miss -h arg");
        return -1;
    }

    int port_int;
    if (port == NULL)
    {
        LOGW("miss -p arg; use default 83128");
        port_int = 83128;
    }
    else
        port_int = atoi(port);
    if (port_int < 0 || port_int > 65535)
    {
        LOGE("bad port(%d)", port_int);
        return -1;
    }
    free(remote_host);
    remote_host = strdup(host);
    remote_port = port_int;
    return 0;
}
int start_local_server(const char *ip, int port)
{
    LOGD("socks5 server ip = %s; port = %d", ip, port);
    if (ip == NULL || strlen(ip) == 0)
    {
        return -1;
    }

    int ipv6 = 0;
    size_t i;
    for (i = 0; i < strlen(ip); i++)
    {
        if (ip[i] == ':')
        {
            ipv6 = 1;
            break;
        }
    }

    char addr_str[strlen(ip) + 7];
    bzero(addr_str, sizeof(addr_str));
    if (ipv6)
    {
        sprintf(addr_str, "[%s]:%d", ip, port);
    }
    else
    {
        sprintf(addr_str, "%s:%d", ip, port);
    }

    struct sockaddr_storage addr;

    int addr_len = sizeof(addr);
    if (evutil_parse_sockaddr_port(addr_str, (struct sockaddr *)&addr, &addr_len))
    {
        LOGE("parse sockaddr failed");
        return -1;
    }

    // init openssl
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    int r = RAND_poll();
    if (r == 0)
    {
        LOGE("RAND_poll() failed.\n");
        return 1;
    }
    ssl_ctx = SSL_CTX_new(TLS_method());

    base = event_base_new();
    if (base == NULL)
    {
        LOGE("event_base_new: failed, errno = %d; %s", errno, strerror(errno));
        return -1;
    }

    dns_base = evdns_base_new(base, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
    evdns_base_nameserver_ip_add(dns_base, "1.1.1.1");

    struct evconnlistener *listener = evconnlistener_new_bind(base, connect_cb, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE, -1, (struct sockaddr *)&addr, addr_len);

    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);
    LOGE("server stoped");
    return -1;
}