#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>

#include "../event/multi_socks_epoll_server.h"
#include "multi_socks.h"
#include "../lib/c_sparse_array.h"
#include "msl.h"
#include "../lib/c_linked_list.h"
#include "../log.h"
#include "../lib/c_array.h"
#include "../lib/clib.h"
#include "../lib/c_hex_utils.h"

#define MULTI_SOCKS_STATUS_REQUEST 10
#define MULTI_SOCKS_STATUS_OK SOCKS_STATUS_DONE
#define MULTI_SOCKS_STATUS_DRAIN 11
#define MULTI_SOCKS_STATUS_CLOSE_WAIT 12

static char *tunnel_host = NULL;
static int tunnel_port = 0;
static int heartbeat_interval = 10;
static time_t last_heartbeat_time = 0;
static unsigned int heartbeat_session = 0;
static unsigned int last_received_headbeat_session = 0;

static char *auth_username = NULL;
static char *auth_password = NULL;

static void tunnel_event_cb(MultiSocksEvent *ev, int what, void *ctx);

struct msl_context
{
    Socks5Context *server;

    char *host;
    int port;
    void *arg;

    msl_connect_cb conn_cb;
    msl_read_cb read_cb;

    unsigned short sequence;
    unsigned int session;
};
typedef MslServerContext ServerContext;

static ServerContext *ServerContext_new()
{
    ServerContext *server = (ServerContext *)calloc(1, sizeof(ServerContext));
    return server;
}

void MslServerContext_arg(MslServerContext *context, void *arg)
{
    if (context == NULL)
        return;

    context->arg = arg;
}

typedef struct
{
    int status;
    CSparseArray *clients;
    CLinkedList *clients_wait_auth;

    MultiSocksBase *base;
    MultiSocksEvent *ev;
    unsigned char connect_count;

    unsigned char seq_index;
} TunnelContext;

static TunnelContext *_tunnel = NULL;

static void ServerContext_free(ServerContext *server)
{
    LOGD("session = %d, sequence = %d", server->session, server->sequence);

    c_linked_list_remove(_tunnel->clients_wait_auth, server);
    void *v = CSparseArray_remove(_tunnel->clients, server->sequence);

    if (v != server)
        LOGD("v = %p, server = %p", v, server);

    if (server->server != NULL)
        Socks5Context_free(server->server);

    server->server = NULL;

    free(server->host);
    server->host = NULL;

    free(server);
}

static TunnelContext *TunnelContext_new()
{
    TunnelContext *tunnel = (TunnelContext *)calloc(1, sizeof(TunnelContext));
    tunnel->clients = CSparseArray_new();
    tunnel->clients_wait_auth = c_linked_list_new();
    tunnel->status = MULTI_SOCKS_STATUS_REQUEST;
    tunnel->seq_index = 0;
    tunnel->connect_count = 0;

    return tunnel;
}

static void reconnect_to_tunnel()
{
    LOGD("reconnect_to_tunnel");
    if (_tunnel->ev)
        multi_socks_epoll_server_event_free(_tunnel->ev);
    _tunnel->ev = NULL;
    _tunnel->connect_count++;
    _tunnel->status = MULTI_SOCKS_STATUS_REQUEST;

    if (_tunnel->connect_count >= 10)
    {
        LOGE("connect to tunnel failed 10 times");
        exit(0);
    }

    c_linked_list_clear(_tunnel->clients_wait_auth);
    void *h = NULL;
    while (CSparseArray_length(_tunnel->clients) > 0 && (h = CSparseArray_remove_last(_tunnel->clients, NULL)) != NULL)
    {
        ServerContext *sc = h;
        if (sc->server == NULL && sc->read_cb != NULL)
            sc->read_cb(sc, NULL, 0, sc->arg);

        ServerContext_free(sc);
    }

    _tunnel->ev = multi_socks_epoll_server_connect_hostname(_tunnel->base, -1, tunnel_host, tunnel_port, _tunnel);
    if (_tunnel->ev == NULL)
    {
        LOGE("connect to tunnel failed");
        exit(-1);
    }

    multi_socks_ev_setcb(_tunnel->ev, NULL, NULL, tunnel_event_cb, _tunnel);
}

static int send_command_without_server(int cmd, char *host, int port, int sequence, unsigned int session, char *data, int d_len)
{
    LOGD("cmd = %x, d_len = %d, sequence = %d, session = %d", cmd, d_len, sequence, session);
    if (_tunnel == NULL || _tunnel->status != MULTI_SOCKS_STATUS_OK)
    {
        LOGE("tunnel is not ready to send command");
        return -1;
    }

    if (cmd != MULTI_SOCKS_CMD_CONNECT)
        host = NULL;

    int host_len = host == NULL ? 0 : strlen(host);

    MultiSocksPacket packet;
    bzero(&packet, sizeof(MultiSocksPacket));
    packet.version = MULTI_SOCKS_VERSION_1;
    packet.cmd = cmd;
    packet.sequence = sequence;
    packet.host = host;
    packet.port = port;
    packet.session = session;
    packet.p_len = 0;
    packet.sum = 0;
    packet.d_len = d_len;
    packet.data = data;
    packet.p_len = 7 + host_len + 2 + 4 + 2 + 2 + d_len;

    char p_data[packet.p_len];
    multi_socks_checksum_and_pack(&packet, p_data);
    LOGD("len = %hu, sum = %x", packet.p_len, packet.sum);
    MultiSocksBuffer *out = multi_socks_ev_get_output(_tunnel->ev);
    if (out == NULL || multi_socks_epoll_server_buffer_write(out, p_data, packet.p_len) == -1)
    {
        LOGE("write to remote failed");
        reconnect_to_tunnel();
        return -1;
    }
    // hexDump(p_data, packet.p_len, 0);
    last_heartbeat_time = time(NULL);

    return 0;
}

static int send_command(ServerContext *server, int cmd, char *data, int d_len)
{
    LOGD("cmd = %x, d_len = %d, session = %x", cmd, d_len, server->session);
    char *host = NULL;
    int port = 0;
    if (server->server != NULL)
        socks5_context_get_remote_address(server->server, &host, &port);
    else
    {
        host = server->host;
        port = server->port;
    }
    return send_command_without_server(cmd, host, port, server->sequence, server->session, data, d_len);
}

static int connect_to_remote(ServerContext *ctx)
{
    LOGD("connect to remote");
    if (_tunnel->ev == NULL)
    {
        return -1;
    }

    if (send_command(ctx, MULTI_SOCKS_CMD_CONNECT, NULL, 0) == -1)
    {
        LOGD("send command failed");
        if (ctx->server == NULL && ctx->read_cb != NULL)
            ctx->read_cb(ctx, NULL, 0, ctx->arg);
        ServerContext_free(ctx);
        reconnect_to_tunnel();
        return -1;
    }

    return 0;
}

static void server_read_cb(MultiSocksEvent *ev, void *ctx)
{
    LOGD("read");

    if (_tunnel->ev == NULL || _tunnel->status != MULTI_SOCKS_STATUS_OK)
    {
        return;
    }

    ServerContext *server = ctx;
    MultiSocksBuffer *in = multi_socks_ev_get_input(ev);
    size_t len = multi_socks_epoll_server_buffer_get_length(in);

    if (len <= 0)
        return;
    char data[len];
    multi_socks_epoll_server_buffer_copyout(in, data, len);
    if (send_command(server, MULTI_SOCKS_CMD_WRITE, data, len) == -1)
    {
        reconnect_to_tunnel();
    }
    multi_socks_epoll_server_buffer_remove(in, len);
}

static void server_event_cb(MultiSocksEvent *ev, int what, void *ctx)
{
    LOGD("what = %x", what);
    ServerContext *server = ctx;
    socks5_context_set_ev(server->server, ev);
    ServerContext_free(server);
}

// -------------------- tunnel --------------------
static void tunnel_read_cb(MultiSocksEvent *ev, void *ctx)
{
    LOGD("read");
    TunnelContext *tunnel = _tunnel;
    MultiSocksBuffer *in = multi_socks_ev_get_input(ev);
    size_t len = multi_socks_epoll_server_buffer_get_length(in);

    if (len <= 4)
    {
        LOGD("len = %zu; we need read more data", len);
        return;
    }
    char head[4];
    if (multi_socks_epoll_server_buffer_copyout(in, head, sizeof(head)) != 4)
    {
        LOGD("copy packet head failed");

        return;
    }

    if (head[0] != MULTI_SOCKS_VERSION_1)
    {
        LOGD("unknown version %d", head[0]);
        reconnect_to_tunnel();
        return;
    }

    int p_len = read_short(head, 2);
    if (len < p_len || p_len <= 4)
    {
        LOGD("need read more data, len = %zu, p_len = %d", len, p_len);
        return;
    }

    char data[p_len];
    if (multi_socks_epoll_server_buffer_copyout(in, data, p_len) != p_len)
    {
        LOGE("read packet data failed");
        reconnect_to_tunnel();
        return;
    }

    LOGD("read packet full (len = %d)", p_len);

    char host[data[6] + 1];
    MultiSocksPacket packet;
    bzero(&packet, sizeof(MultiSocksPacket));

    if (data[6] > 0)
    {
        host[sizeof(host) - 1] = 0;
        strncpy(host, data + 7, data[6]);
        packet.host = host;
    }
    if (!multi_socks_parse_and_verify_checksum(&packet, data))
    {
        LOGE("parse packet failed: p_len = %d, cmd = %d, sum = %x, d_len = %d", packet.p_len, packet.cmd, packet.sum, packet.d_len);
        reconnect_to_tunnel();
        return;
    }
    LOGD("checksum success: session = %d, sequence = %d", packet.session, packet.sequence);

    multi_socks_epoll_server_buffer_remove(in, p_len);

    if (packet.cmd == MULTI_SOCKS_CMD_HEARTBEAT)
    {
        last_received_headbeat_session = packet.session;
        LOGD("last_received_headbeat_session = %d", last_received_headbeat_session);
        return;
    }

    ServerContext *server = CSparseArray_get(tunnel->clients, packet.sequence);
    if (server == NULL)
    {
        if (packet.cmd != MULTI_SOCKS_CMD_CLOSE)
        {
            // TODO send close event
            send_command_without_server(MULTI_SOCKS_CMD_CLOSE, NULL, 0, packet.sequence, packet.session, NULL, 0);
        }
        return;
    }
    MultiSocksEvent *s_ev = NULL;
    if (server->server)
    {
        s_ev = socks5_context_get_ev(server->server);
        if (s_ev == NULL)
        {
            ServerContext_free(server);
            return;
        }
    }

    MultiSocksBuffer *s_out = multi_socks_ev_get_output(s_ev);

    LOGD("cmd = %d", packet.cmd);
    if (packet.cmd == MULTI_SOCKS_CMD_CONNECT_RESULT)
    {
        // send success message to client
        char *reply_data;
        size_t reply_len;
        server->session = packet.session;

        if (s_ev)
        {
            socks5_context_get_reply_data(server->server, &reply_data, &reply_len);
            if (reply_data == NULL)
            {
                LOGE("server is closed.");
                ServerContext_free(server);
                return;
            }

            int auth_success = 0;
            if (packet.d_len == 1 && packet.data[0] == SOCKS_USERNAME_PASSWORD_AUTH_SUCCESS)
                auth_success = 1;
            else
                reply_data[1] = SOCKS5_REPLY_NETWORK_UNREACHABLE;

            LOGD("connect result: %s", auth_success ? "success" : "failure");
            if (multi_socks_epoll_server_buffer_write(s_out, reply_data, reply_len) == -1)
            {
                LOGE("write reply data to client failed");
                ServerContext_free(server);
                return;
            }

            multi_socks_ev_setcb(s_ev, server_read_cb, NULL, server_event_cb, server);
        }
        else
        {
            if (server->conn_cb)
            {
                if (packet.d_len == 1 && packet.data[0] == SOCKS_USERNAME_PASSWORD_AUTH_SUCCESS)
                    server->conn_cb(server, CONNECT_OK, server->arg);
                else
                {
                    server->conn_cb(server, CONNECT_FAILED, server->arg);
                    ServerContext_free(server);
                }
            }
        }
    }
    else if (packet.cmd == MULTI_SOCKS_CMD_WRITE)
    {
        if (server->server)
        {
            if (multi_socks_epoll_server_buffer_write(s_out, packet.data, packet.d_len) == -1)
            {
                LOGE("write data failed");
                ServerContext_free(server);
            }
        }
        else
        {
            if (server->read_cb == NULL || server->read_cb(server, packet.data, packet.d_len, server->arg) == -1)
            {
                LOGE("write data failed");
                send_command_without_server(MULTI_SOCKS_CMD_CLOSE, NULL, 0, packet.sequence, packet.session, NULL, 0);
                ServerContext_free(server);
            }
        }
    }
    else if (packet.cmd == MULTI_SOCKS_CMD_CLOSE)
    {
        if (server->server == NULL)
        {
            if (server->read_cb == NULL || server->read_cb(server, NULL, 0, server->arg) == -1)
            {
                LOGE("write data failed");
                send_command_without_server(MULTI_SOCKS_CMD_CLOSE, NULL, 0, packet.sequence, packet.session, NULL, 0);
            }
        }
        ServerContext_free(server);
    }

    len = multi_socks_epoll_server_buffer_get_length(in);
    if (len > 4)
        tunnel_read_cb(ev, ctx);
}

static void tunnel_auth_read_cb(MultiSocksEvent *ev, void *ctx)
{
    TunnelContext *tunnel = ctx;
    MultiSocksBuffer *in = multi_socks_ev_get_input(ev);
    size_t len = multi_socks_epoll_server_buffer_get_length(in);

    if (len < 3)
    {
        LOGD("wait and read more data");
        return;
    }

    char buf[3];
    multi_socks_epoll_server_buffer_copyout(in, buf, 3);
    LOGD("auth info %x %x %x", buf[0], buf[1], buf[2]);
    if (buf[0] == MULTI_SOCKS_VERSION_1 && buf[1] == 0x00 && buf[2] == SOCKS_USERNAME_PASSWORD_AUTH_SUCCESS)
    {
        multi_socks_epoll_server_buffer_remove(in, 3);
        tunnel->status = MULTI_SOCKS_STATUS_OK;
        multi_socks_ev_setcb(ev, tunnel_read_cb, NULL, tunnel_event_cb, tunnel);

        // send connect request to server
        if (tunnel->clients_wait_auth != NULL)
        {
            LOGD("send connect command");
            ServerContext *c;

            while ((c = c_linked_list_remove_header(tunnel->clients_wait_auth)) != NULL)
            {
                if (connect_to_remote(c) == -1)
                    break;
            }
        }
    }
    else
        reconnect_to_tunnel();
}

static void tunnel_heartbeat_cb(MultiSocksTimer *t, void *ctx)
{
    LOGD("timer");
    TunnelContext *tunnel = _tunnel;
    time_t now = time(NULL);
    LOGD("now = %ld, last_heartbeat_time = %ld， tunnel = %p, tunnel->ev = %p", now, last_heartbeat_time, tunnel, tunnel != NULL ? tunnel->ev : NULL);
    if (tunnel != NULL && tunnel->ev != NULL)
    {
        // check heartbeat session
        if (heartbeat_session != last_received_headbeat_session)
        {
            LOGD("heartbeat_session = %d, last_received_headbeat_session = %d", heartbeat_session, last_received_headbeat_session);
            heartbeat_session = last_received_headbeat_session = 0;
            reconnect_to_tunnel();
            return;
        }

        heartbeat_session++;
        send_command_without_server(MULTI_SOCKS_CMD_HEARTBEAT, NULL, 0, 0, heartbeat_session, NULL, 0);
    }
}

static void tunnel_event_cb(MultiSocksEvent *ev, int what, void *ctx)
{
    LOGD("what = %x", what);
    TunnelContext *tunnel = ctx;
    tunnel->ev = ev;
    if ((what & MULTI_SOCKS_EV_CONNECT) && !(what & MULTI_SOCKS_EV_ERROR))
    {
        tunnel->connect_count = 0;
        LOGD("on connect");
        multi_socks_ev_setcb(ev, tunnel_auth_read_cb, NULL, tunnel_event_cb, ctx);

        MultiSocksBuffer *out = multi_socks_ev_get_output(ev);
        size_t u_l = strlen(auth_username);
        size_t p_l = strlen(auth_password);

        char auth_info[3 + 1 + u_l + 1 + p_l];
        auth_info[0] = MULTI_SOCKS_VERSION_1;
        auth_info[1] = MULTI_SOCKS_AUTH_TYPE_USERNAME_PASSWORD;
        auth_info[2] = 0;

        auth_info[3] = u_l;
        memcpy(auth_info + 4, auth_username, u_l);

        auth_info[4 + u_l] = p_l;
        memcpy(auth_info + 4 + u_l + 1, auth_password, p_l);

        multi_socks_epoll_server_buffer_write(out, auth_info, sizeof(auth_info));
        LOGD("sending auth info");

        multi_socks_epoll_server_event_set_timer(ev, heartbeat_interval * 1000, tunnel_heartbeat_cb, ev);
    }
    else
    {
        LOGE("wait 5s reconnect to tunnel...");
        sleep(5);
        reconnect_to_tunnel();
    }
}

static void tunnel_init(MultiSocksBase *base)
{
    if (_tunnel == NULL)
    {
        if (tunnel_host == NULL || tunnel_port < 0 || tunnel_port > 65535)
        {
            LOGE("tunnel need setup host and port");
            exit(-1);
        }

        TunnelContext *tunnel = TunnelContext_new();
        tunnel->base = base;
        tunnel->ev = multi_socks_epoll_server_connect_hostname(tunnel->base, -1, tunnel_host, tunnel_port, tunnel);
        if (tunnel->ev == NULL)
        {
            LOGE("connect to tunnel failed");
            exit(-1);
        }

        multi_socks_ev_setcb(tunnel->ev, NULL, NULL, tunnel_event_cb, tunnel);
        _tunnel = tunnel;
    }
}

static void connect_internal(Socks5Context *context, MultiSocksBase *base, char *host, int port, msl_connect_cb cb, msl_read_cb read_cb, void *arg)
{
    if (context)
        tunnel_init(socks5_context_get_base(context));
    else
        tunnel_init(base);
    ServerContext *server = ServerContext_new();
    server->server = context;
    server->host = host;
    server->port = port;
    server->conn_cb = cb;
    server->read_cb = read_cb;
    server->arg = arg;

    while (CSparseArray_get(_tunnel->clients, _tunnel->seq_index) != NULL)
    {
        _tunnel->seq_index++;
    }
    server->sequence = _tunnel->seq_index;
    _tunnel->seq_index++;

    CSparseArray_put(_tunnel->clients, server->sequence, server);
    multi_socks_ev_setcb(socks5_context_get_ev(server->server), NULL, NULL, server_event_cb, server);

    if (_tunnel->ev == NULL || _tunnel->status != MULTI_SOCKS_STATUS_OK)
    {
        LOGD("add to wait list");
        c_linked_list_add(_tunnel->clients_wait_auth, server);
    }
    else
        connect_to_remote(server);
}

void multi_socks_connect_to_remote(Socks5Context *context)
{
    connect_internal(context, NULL, NULL, 0, NULL, NULL, NULL);
}

void msl_connect(MultiSocksBase *base, char *host, int port, msl_connect_cb conn_cb, msl_read_cb read_cb, void *arg)
{
    return connect_internal(NULL, base, strdup(host), port, conn_cb, read_cb, arg);
}

int msl_write(MslServerContext *ctx, char *data, size_t len)
{
    if (ctx == NULL)
        return -1;

    send_command(ctx, MULTI_SOCKS_CMD_WRITE, data, len);
    return 0;
}

int msl_close(MslServerContext *ctx)
{
    if (ctx == NULL)
        return -1;
    send_command(ctx, MULTI_SOCKS_CMD_CLOSE, NULL, 0);
    return 0;
}

void multi_socks_set_auth_info(char *username, char *password)
{
    free(auth_username);
    auth_username = strdup(username);
    free(auth_password);
    auth_password = strdup(password);
}

void set_multi_socks_server(char *host, char *port)
{
    LOGD("ms server %s:%s", host, port);

    free(tunnel_host);
    tunnel_host = strdup(host);
    tunnel_port = atoi(port);
}

void multi_socks_set_heartbeat(int interval)
{
    heartbeat_interval = interval;
}