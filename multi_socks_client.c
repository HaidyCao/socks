#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "event2/util.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/event.h"
#include "event2/listener.h"
#include "event2/dns.h"
#include "event2/event-config.h"

#include "multi_socks.h"
#include "multi_socks_client.h"
#include "c_array_map.h"
#include "log.h"
#include "c_array.h"
#include "libevent_utils_ext.h"

#define MULTI_SOCKS_STATUS_REQUEST 10
#define MULTI_SOCKS_STATUS_OK SOCKS_STATUS_DONE
#define MULTI_SOCKS_STATUS_DRAIN 11
#define MULTI_SOCKS_STATUS_CLOSE_WAIT 12

#define MAX_OUTPUT (512 * 1024)

#define free_remote_context_bev(remote)  \
    {                                    \
        LOGD("free_remote_context_bev"); \
        bufferevent_free(remote->bev);   \
        reconnect_to_server();           \
    }

static char *remote_addr;
static char *remote_port;

static char *username;
static char *password;

static char *cert_data;

static struct evdns_base *dns_base;
static struct event_base *base;

struct multi_socks_remote
{
    struct bufferevent *bev;
    int status;
    Array *client_array;
    Array *client_read_disabled_array;
    int error_count;
    CArrayMap *client_map;

    CArrayMap *sequence_map;
    int sequence;
};

typedef struct multi_socks_remote MultiSocksRemote;

struct multi_socks_client
{
    SocksContext *ctx;
    int sequence;
    int session;
};

typedef struct multi_socks_client MultiSocksClient;

static MultiSocksRemote *remote_context = NULL;

static const struct timeval connect_timeout = {60 * 5, 0};

static void reconnect_to_server();

static int send_command_reply(MultiSocksPacket *old_packet, int cmd, char *data, int d_len);
static int send_command(MultiSocksClient *client, int cmd, char *data, int len);

static void multi_socks_client_event_cb(struct bufferevent *bev, short what, void *ctx);
static void multi_socks_tunnel_event_cb(struct bufferevent *bev, short what, void *ctx);

static void tunnel_write_data_cb(struct bufferevent *bev, void *ctx);
static void client_write_data_cb(struct bufferevent *bev, void *ctx);

static void tunnel_read_data_cb(struct bufferevent *bev, void *ctx);
static void client_read_data_cb(struct bufferevent *bev, void *ctx);

static void free_multi_socks_client(void *v)
{
    MultiSocksClient *client = (MultiSocksClient *)v;
    LOGD("client session = %x, sequence = %x", client->session, client->sequence)
    free_socks_context(client->ctx);
    if (client->sequence != -1)
        c_array_map_remove(remote_context->sequence_map, client->sequence);
    free(client);
}

static void client_drained_write_cb(struct bufferevent *bev, void *ctx)
{
    MultiSocksClient *client = (MultiSocksClient *)ctx;
    SocksContext *context = client->ctx;

    bufferevent_setcb(bev, client_read_data_cb, client_write_data_cb, multi_socks_client_event_cb, ctx);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);

    if (remote_context->status == MULTI_SOCKS_STATUS_OK)
    {
        send_command(client, MULTI_SOCKS_CMD_FREE_DRAIN, NULL, 0);
    }
}

static void server_drained_write_cb(struct bufferevent *bev, void *ctx)
{
    MultiSocksRemote *remote = (MultiSocksRemote *)ctx;
    bufferevent_setcb(bev, tunnel_read_data_cb, tunnel_write_data_cb, multi_socks_tunnel_event_cb, ctx);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);

    Array *array = remote->client_read_disabled_array;
    FOR_ARRAY_EACH(array, { // => void *v
        MultiSocksClient *client = (MultiSocksClient *)v;
        if (client->ctx == NULL)
            continue;

        bufferevent_enable(client->ctx->bev, EV_READ);
    });
    array_clear(array);
}

static void tunnel_read_data_cb(struct bufferevent *bev, void *ctx)
{
    LOGD("");
    MultiSocksRemote *remote = (MultiSocksRemote *)ctx;

    EV_BUF *in = bufferevent_get_input(bev);

    int len = evbuffer_get_length(in);

    if (len < 4)
    {
        LOGD("len = %d; we need read more data", len);
        return;
    }

    char head[4];
    if (evbuffer_copyout(in, head, sizeof(head)) != 4)
    {
        LOGD("copy packet head failed");

        return;
    }

    if (head[0] != MULTI_SOCKS_VERSION_1)
    {
        free_remote_context_bev(remote_context);
        return;
    }

    int p_len = read_short(head, 2);
    if (len < p_len)
    {
        LOGD("need read more data");
        return;
    }

    char data[p_len];
    if (evbuffer_copyout(in, data, p_len) != p_len)
    {
        LOGE("read packet data failed");
        return;
    }

    LOGD("read packet full (len = %d)", p_len);
    MultiSocksPacket packet;
    bzero(&packet, sizeof(MultiSocksPacket));
    if (!multi_socks_parse_and_verify_checksum(&packet, data))
    {
        LOGE("parse packet failed: p_len = %d, cmd = %d, sum = %x, d_len = %d", packet.p_len, packet.cmd, packet.sum, packet.d_len);
        free_remote_context_bev(remote_context);
        return;
    }
    LOGD("checksum success")
    if (evbuffer_drain(in, p_len) == -1)
    {
        LOGE("drain data failed");
        free_remote_context_bev(remote);
        return;
    }

    MultiSocksClient *client = (MultiSocksClient *)c_array_map_get(remote_context->sequence_map, packet.sequence); //remote_context->sequence_array[packet.sequence];
    if (client == NULL)
    {
        LOGD("find client by sequence (%x) failed", packet.sequence);
        send_command_reply(&packet, MULTI_SOCKS_CMD_CLOSE, NULL, 0);
        return;
    }

    LOGD("cmd = %d", packet.cmd);
    if (packet.cmd == MULTI_SOCKS_CMD_CONNECT_RESULT)
    {
        // send success message to client
        int auth_success = 0;
        if (packet.d_len == 1 && packet.data[0] == SOCKS_USERNAME_PASSWORD_AUTH_SUCCESS)
            auth_success = 1;
        else
            client->ctx->reply_data[1] = SOCKS5_REPLY_NETWORK_UNREACHABLE;

        LOGD("connect result: %s", auth_success ? "success" : "failure");
        if (bufferevent_write(client->ctx->bev, client->ctx->reply_data, client->ctx->reply_data_len) != 0)
        {
            LOGE("write reply data to client failed")
            free(client->ctx->reply_data);
            client->ctx->reply_data = NULL;
            return;
        }

        free(client->ctx->reply_data);
        client->ctx->reply_data = NULL;

        if (auth_success)
        {
            client->ctx->status = MULTI_SOCKS_STATUS_OK;
            client->session = packet.session;
            LOGD("client (session = %d) ready translate data through tunnel", client->session);
        }
        else
            client->ctx->status = MULTI_SOCKS_STATUS_CLOSE_WAIT;
    }
    else if (packet.cmd == MULTI_SOCKS_CMD_CLOSE)
    {
        free_multi_socks_client(client);
    }
    else if (packet.cmd == MULTI_SOCKS_CMD_WRITE)
    {
        LOGD("write data to clent(%s:%d) session = %x", client->ctx->remote_addr, client->ctx->remote_port, client->session);
        if (bufferevent_write(client->ctx->bev, packet.data, packet.d_len) == -1)
        {
            LOGE("write data to client failed");
            free_socks_context(client->ctx);
            client->ctx = NULL;
            return;
        }

        EV_BUF *out = bufferevent_get_output(client->ctx->bev);
        if (evbuffer_get_length(out) > MAX_OUTPUT)
        {
            bufferevent_setcb(client->ctx->bev, client_read_data_cb, client_drained_write_cb, multi_socks_client_event_cb, client);
            bufferevent_setwatermark(client->ctx->bev, EV_WRITE, MAX_OUTPUT / 2, MAX_OUTPUT);
            send_command(client, MULTI_SOCKS_CMD_DRAIN, NULL, 0);
        }
    }

    tunnel_read_data_cb(bev, ctx);
}

static void client_read_data_cb(struct bufferevent *bev, void *ctx)
{
    LOGD("")
    MultiSocksClient *client = (MultiSocksClient *)ctx;
    SocksContext *context = client->ctx;

    if (remote_context->status != MULTI_SOCKS_STATUS_OK)
    {
        LOGD("multi socks tunnel is not ready")
        return;
    }

    // check whether the server needs drain
    EV_BUF *out = bufferevent_get_output(remote_context->bev);
    if (evbuffer_get_length(out) > MAX_OUTPUT)
    {
        LOGD("tunnel set watermark")
        bufferevent_setcb(remote_context->bev, tunnel_read_data_cb, server_drained_write_cb, multi_socks_tunnel_event_cb, remote_context);
        bufferevent_setwatermark(remote_context->bev, EV_WRITE, MAX_OUTPUT / 2, MAX_OUTPUT);
        bufferevent_disable(bev, EV_READ);
        array_add(remote_context->client_read_disabled_array, client);
        return;
    }

    EV_BUF *in = bufferevent_get_input(bev);

    int len = evbuffer_get_length(in);

    char data[len];

    int remove_result = evbuffer_copyout(in, data, len);
    if (remove_result != len)
    {
        LOGD("copy data from client buf failed");
        free_multi_socks_client(ctx);
        return;
    }

    if (send_command(client, MULTI_SOCKS_CMD_WRITE, data, len) == -1)
    {
        LOGD("wait new tunnel connect");
        return;
    }

    if (evbuffer_drain(in, len))
    {
        LOGE("drain data failed");
        free_multi_socks_client(client);
        return;
    }

    if (evbuffer_get_length(out) > MAX_OUTPUT)
    {
        LOGD("tunnel set watermark")
        bufferevent_setcb(remote_context->bev, tunnel_read_data_cb, server_drained_write_cb, multi_socks_tunnel_event_cb, remote_context);
        bufferevent_setwatermark(remote_context->bev, EV_WRITE, MAX_OUTPUT / 2, MAX_OUTPUT);
        bufferevent_disable(bev, EV_READ);
        array_add(remote_context->client_read_disabled_array, client);
    }
}

static void tunnel_write_data_cb(struct bufferevent *bev, void *ctx)
{
    EV_BUF *out = bufferevent_get_output(bev);
    EV_BUF *in = bufferevent_get_input(bev);
    LOGD("output len = %zu; input len = %zu", evbuffer_get_length(out), evbuffer_get_length(in));
}

static void client_write_data_cb(struct bufferevent *bev, void *ctx)
{
    LOGD("")
}

static void multi_socks_client_event_cb(struct bufferevent *bev, short what, void *ctx)
{
    LOGD("what = %x", what);
    if (what & (BEV_EVENT_READING | BEV_EVENT_WRITING | BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT))
    {
        // remove
        if (remote_context != NULL && remote_context->client_read_disabled_array != NULL)
            array_remove_by_value(remote_context->client_read_disabled_array, ctx);

        send_command((MultiSocksClient *)ctx, MULTI_SOCKS_CMD_CLOSE, NULL, 0);
        // free client
        free_multi_socks_client(ctx);
    }
}

static void multi_socks_tunnel_event_cb(struct bufferevent *bev, short what, void *ctx)
{
    LOGD("what = %x, ctx = %p", what, ctx);
    MultiSocksRemote *remote = (MultiSocksRemote *)ctx;
    if (what & (BEV_EVENT_READING | BEV_EVENT_WRITING | BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT))
    {
        // reconnect to server
        LOGD("tunnel is closed");
        free_remote_context_bev(remote);
    }
    else if (what & BEV_EVENT_CONNECTED)
    {
        LOGD("connect to tunnel (%s:%s) server success", remote_addr, remote_port);

        remote->status = MULTI_SOCKS_STATUS_REQUEST;
        // start translate data

        // start login
        size_t u_l = strlen(username);
        size_t p_l = strlen(password);

        char auth_info[3 + 1 + u_l + 1 + p_l];
        auth_info[0] = MULTI_SOCKS_VERSION_1;
        auth_info[1] = MULTI_SOCKS_AUTH_TYPE_USERNAME_PASSWORD;
        auth_info[2] = 0;

        auth_info[3] = u_l;
        memcpy(auth_info + 4, username, u_l);

        auth_info[4 + u_l] = p_l;
        memcpy(auth_info + 4 + u_l + 1, password, p_l);
        if (bufferevent_write(remote_context->bev, auth_info, sizeof(auth_info)) == -1)
        {
            LOGE("write auth info to server failed.")
            free_remote_context_bev(remote);
            return;
        }
        LOGD("ready send auth info to remote server");
        bufferevent_set_timeouts(bev, &connect_timeout, &connect_timeout);
    }
}

static int connect_to_remote(MultiSocksClient *client)
{
    if (send_command(client, MULTI_SOCKS_CMD_CONNECT, NULL, 0) == -1)
    {
        return -1;
    }

    client->sequence = remote_context->sequence;

    c_array_map_put(remote_context->sequence_map, remote_context->sequence, client);
    remote_context->sequence++;
    LOGD("client (%s:%d) sequence = %x", client->ctx->remote_addr, client->ctx->remote_port, client->sequence);
    return 0;
}

static int send_command_reply(MultiSocksPacket *old_packet, int cmd, char *data, int d_len)
{
    MultiSocksPacket packet;
    bzero(&packet, sizeof(MultiSocksPacket));
    packet.version = MULTI_SOCKS_VERSION_1;
    packet.cmd = cmd;
    packet.sequence = old_packet->sequence;
    packet.host = old_packet->host;
    packet.port = old_packet->port;
    packet.session = old_packet->session;
    packet.p_len = 0;
    packet.sum = 0;
    packet.d_len = d_len;
    packet.data = data;
    packet.p_len = 7 + strlen(packet.host) + 2 + 2 + 2 + 2 + d_len;

    char p_data[packet.p_len];
    multi_socks_checksum_and_pack(&packet, p_data);
    LOGD("len = %hu, sum = %x", packet.p_len, packet.sum);
    if (bufferevent_write(remote_context->bev, p_data, packet.p_len) == -1)
    {
        LOGD("write to remote failed")
        free_remote_context_bev(remote_context);
        return -1;
    }
    hexDump(p_data, packet.p_len, 0);

    return 0;
}

static int send_command(MultiSocksClient *client, int cmd, char *data, int d_len)
{
    LOGD("cmd = %x, d_len = %d, session = %x", cmd, d_len, client->session);
    if (cmd == MULTI_SOCKS_CMD_CLOSE && client->session == -1)
    {
        LOGI("send command failed: not connect to remote")
        return -1;
    }

    MultiSocksPacket packet;
    bzero(&packet, sizeof(MultiSocksPacket));
    packet.version = MULTI_SOCKS_VERSION_1;
    packet.cmd = cmd;
    packet.sequence = remote_context->sequence;
    packet.host = client->ctx->remote_addr;
    packet.port = client->ctx->remote_port;
    packet.session = client->session;
    packet.p_len = 0;
    packet.sum = 0;
    packet.d_len = d_len;
    packet.data = data;
    packet.p_len = 7 + strlen(packet.host) + 2 + 2 + 2 + 2 + d_len;

    char p_data[packet.p_len];
    multi_socks_checksum_and_pack(&packet, p_data);
    LOGD("len = %hu, sum = %x", packet.p_len, packet.sum);
    if (bufferevent_write(remote_context->bev, p_data, packet.p_len) == -1)
    {
        LOGD("write to remote failed")
        free_remote_context_bev(remote_context);
        return -1;
    }
    hexDump(p_data, packet.p_len, 0);

    return 0;
}

static void multi_socks_negotication_read_cb(struct bufferevent *bev, void *ctx)
{
    LOGD("");
    MultiSocksRemote *remote = (MultiSocksRemote *)ctx;
    if (remote->status == MULTI_SOCKS_STATUS_REQUEST)
    {
        LOGD("read auth result");
        EV_BUF *input = bufferevent_get_input(bev);
        int input_legnth = evbuffer_get_length(input);
        if (input_legnth < 3)
        {
            LOGD("wait and read more data");
            return;
        }

        char buf[3];
        bzero(buf, sizeof(buf));
        if (evbuffer_remove(input, buf, sizeof(buf)) != 3)
        {
            LOGE("read data error");
            free_remote_context_bev(remote);
            return;
        }
        LOGD("auth info %x %x %x", buf[0], buf[1], buf[2]);
        if (buf[0] == MULTI_SOCKS_VERSION_1 && buf[1] == 0x00 && buf[2] == SOCKS_USERNAME_PASSWORD_AUTH_SUCCESS)
        {
            remote->status = MULTI_SOCKS_STATUS_OK;
            bufferevent_setcb(bev, tunnel_read_data_cb, tunnel_write_data_cb, multi_socks_tunnel_event_cb, remote);

            // send connect request to server
            if (remote->client_array != NULL && remote->client_array->len > 0)
            {
                LOGD("send connect command");
                Array *array = remote->client_array;
                int reconnect = 0;
                FOR_ARRAY_EACH(array, { // => void* v
                    if (connect_to_remote((MultiSocksClient *)v) == -1)
                    {
                        reconnect = 1;
                        break;
                    }
                });
                if (reconnect)
                {
                    LOGD("need reconnect to tunnel");
                    free_remote_context_bev(remote);
                }

                array_clear(array);
            }
        }
        else
            free_remote_context_bev(remote);
        return;
    }
    LOGE("bad read cb");

    // will reconnect to server
    free_remote_context_bev(remote);
}

static void reconnect_to_server()
{
    remote_context->bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

    LOGE("connect to remote (%s %s)", remote_addr, remote_port);
    if (bufferevent_socket_connect_hostname(remote_context->bev, dns_base, AF_UNSPEC, remote_addr, atoi(remote_port)) == -1)
    {
        LOGE("connect to remote (%s %s) failed", remote_addr, remote_port);
        bufferevent_free(remote_context->bev);
        if (remote_context->error_count > 10)
        {
            exit(-1);
        }
        remote_context->error_count++;
        return;
    }

    bufferevent_setcb(remote_context->bev, multi_socks_negotication_read_cb, tunnel_write_data_cb, multi_socks_tunnel_event_cb, remote_context);
    bufferevent_enable(remote_context->bev, EV_READ | EV_WRITE);
}

void multi_socks_set_auth_info(char *u, char *p)
{
    free(username);
    free(password);

    username = strdup(u);
    password = strdup(p);
}

void multi_socks_connect_to_remote(SocksContext *context)
{
    LOGD("connect remote to %s:%d through multi socks tunnel(%s:%s)", context->remote_addr, context->remote_port, remote_addr, remote_port);
    MultiSocksClient *client = (MultiSocksClient *)malloc(sizeof(MultiSocksClient));
    bzero(client, sizeof(MultiSocksClient));
    client->ctx = context;
    client->session = -1;
    client->sequence = -1;

    if (remote_context == NULL)
    {
        dns_base = context->ss->dns_base;
        base = context->ss->base;
        // connect to remote server
        remote_context = (MultiSocksRemote *)malloc(sizeof(MultiSocksRemote));
        bzero(remote_context, sizeof(MultiSocksRemote));
        remote_context->status = SOCKS_STATUS_CONNECT;
        remote_context->bev = bufferevent_socket_new(context->ss->base, -1, BEV_OPT_CLOSE_ON_FREE);

        LOGD("connect to remote (%s %s)", remote_addr, remote_port);
        if (bufferevent_socket_connect_hostname(remote_context->bev, dns_base, AF_UNSPEC, remote_addr, atoi(remote_port)) == -1)
        {
            LOGE("connect to remote (%s %s) failed", remote_addr, remote_port);
            free_socks_context(context);
            bufferevent_free(remote_context->bev);
            free(remote_context);
            remote_context = NULL;
            return;
        }

        remote_context->error_count = 0;
        remote_context->client_array = (Array *)malloc(sizeof(Array));
        bzero(remote_context->client_array, sizeof(Array));
        array_init(remote_context->client_array);
        remote_context->client_array->free_cb = NULL;

        // init client read disabled array
        remote_context->client_read_disabled_array = (Array *)malloc(sizeof(Array));
        bzero(remote_context->client_read_disabled_array, sizeof(Array));
        array_init(remote_context->client_read_disabled_array);

        remote_context->sequence_map = c_array_map_new();
        remote_context->sequence = 0;

        bufferevent_setcb(remote_context->bev, multi_socks_negotication_read_cb, tunnel_write_data_cb, multi_socks_tunnel_event_cb, remote_context);
        bufferevent_enable(remote_context->bev, EV_READ | EV_WRITE);
    }

    LOGD("remote_context status = %d", remote_context->status);
    if (remote_context->status != MULTI_SOCKS_STATUS_OK)
        array_add(remote_context->client_array, client);
    else
        connect_to_remote(client);

    bufferevent_setcb(context->bev, client_read_data_cb, client_write_data_cb, multi_socks_client_event_cb, client);

    if (username == NULL || password == NULL)
    {
        LOGE("username or password is null");
        exit(0);
    }
}

void set_multi_socks_server(char *host, char *port)
{
    remote_addr = host;
    remote_port = port;
}

void init_multi_socks_client()
{
}