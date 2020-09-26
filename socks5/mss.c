#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <strings.h>

#include "c_sparse_array.h"
#include "c_hash_map.h"
#include "multi_socks.h"
#include "log.h"
#include "clib.h"
#include "../event/multi_socks_epoll_server.h"
#include "socks5.h"
#include "c_hex_utils.h"

#define MSS_REMOTE_STATUS_CONNECTING 0
#define MSS_REMOTE_STATUS_OK 1
#define MSS_REMOTE_STATUS_CLOSED 2

static unsigned int remote_sequence = 0;
static CSparseArray *remotes_map = NULL;
static char *dns_server = NULL;

static MultiSocksBase *base = NULL;
static CHashMap *auth_map = NULL;

static char CONNECT_SUCCESS_RESULT[] = {SOCKS_USERNAME_PASSWORD_AUTH_SUCCESS};
static char CONNECT_FAILURE_RESULT[] = {0xff};

static char check_username_password(char *username, char *password)
{
    if (auth_map == NULL)
    {
        return SOCKS_USERNAME_PASSWORD_AUTH_SUCCESS;
    }

    char *p = c_hash_map_get(auth_map, username);
    if (p != NULL && strcmp(password, p) == 0)
    {
        LOGD("username = %s auth success", username);
        return SOCKS_USERNAME_PASSWORD_AUTH_SUCCESS;
    }

    return 0x01;
}

typedef struct
{
    int status;
    CSparseArray *remotes;
    MultiSocksEvent *ev;
} TunnelContext;

static TunnelContext *TunnelContext_new()
{
    TunnelContext *tunnel = (TunnelContext *)calloc(1, sizeof(TunnelContext));
    tunnel->status = 0;
    tunnel->remotes = CSparseArray_new();
    return tunnel;
}

static void TunnelContext_free(TunnelContext *tunnel);

typedef struct
{
    int status;

    MultiSocksEvent *ev;
    char *host;
    int port;

    unsigned short sequence; // from client
    unsigned int session;    // server

    TunnelContext *tunnel;
} RemoteContext;

static RemoteContext *RemoteContext_new()
{
    RemoteContext *remote = (RemoteContext *)calloc(1, sizeof(RemoteContext));
    remote->status = MSS_REMOTE_STATUS_CONNECTING;
    remote->host = NULL;
    return remote;
}

static void RemoteContext_free(RemoteContext *remote)
{
    LOGI("remove remotes_map key = %d", remote->session);
    CSparseArray_remove(remotes_map, remote->session);
    if (remote->tunnel)
        CSparseArray_remove(remote->tunnel->remotes, remote->session);
    free(remote->host);
    free(remote);
}

static void TunnelContext_free(TunnelContext *tunnel)
{
    CSparseArray_FOR(tunnel->remotes, key, value, { // => i, v
        RemoteContext *remote = value;
        remote->tunnel = NULL;
    });
    CSparseArray_free(tunnel->remotes, NULL);
    free(tunnel);
    return;
}

static int send_command_to_tunnel(TunnelContext *tunnel, MultiSocksPacket *old_packet, int cmd, char *data, size_t d_len)
{
    LOGD("cmd = %d, sequence = %d, session = %d", cmd, old_packet->sequence, old_packet->session);
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
    packet.p_len = 7 + (packet.host == NULL ? 0 : strlen(packet.host)) + 2 + 4 + 2 + 2 + d_len;

    char p_data[packet.p_len];
    multi_socks_checksum_and_pack(&packet, p_data);
    free(packet.host);

    MultiSocksBuffer *out = multi_socks_ev_get_output(tunnel->ev);
    if (multi_socks_epoll_server_buffer_write(out, p_data, (size_t)packet.p_len) == -1)
    {
        LOGE("multi_socks_epoll_server_buffer_write failed");
        if (tunnel->ev)
            multi_socks_epoll_server_event_free(tunnel->ev);
        TunnelContext_free(tunnel);
        return -1;
    }
    return 0;
}

static int send_command(RemoteContext *remote, int cmd, char *data, size_t d_len)
{
    if (remote->tunnel == NULL || remote->tunnel->ev == NULL)
    {
        LOGD("remote tunnel can not write data");
        return -1;
    }

    MultiSocksPacket packet;
    bzero(&packet, sizeof(MultiSocksPacket));
    packet.version = MULTI_SOCKS_VERSION_1;
    packet.cmd = cmd;
    packet.sequence = remote->sequence;
    packet.host = remote->host;
    packet.port = remote->port;
    packet.session = remote->session;
    packet.p_len = 0;
    packet.sum = 0;
    packet.d_len = d_len;
    packet.data = data;
    packet.p_len = 7 + (packet.host == NULL ? 0 : strlen(packet.host)) + 2 + 4 + 2 + 2 + d_len;

    char p_data[packet.p_len];
    bzero(p_data, sizeof(p_data));
    multi_socks_checksum_and_pack(&packet, p_data);
    LOGI("sequence = %d, session = %d, len = %hu, sum = %x", remote->sequence, remote->session, packet.p_len, packet.sum);
    hexDump(p_data + 7 + (packet.host == NULL ? 0 : strlen(packet.host)) + 2, 4, 0);

    MultiSocksBuffer *out = multi_socks_ev_get_output(remote->tunnel->ev);
    if (multi_socks_epoll_server_buffer_write(out, p_data, (size_t)packet.p_len) == -1)
    {
        LOGE("multi_socks_epoll_server_buffer_write failed");
        if (remote->tunnel->ev)
            multi_socks_epoll_server_event_free(remote->tunnel->ev);
        TunnelContext_free(remote->tunnel);

        return 1;
    }
    return 0;
}

/* static void remote_write_cb(MultiSocksEvent *event, void *ctx)
{
    MultiSocksBuffer *in = multi_socks_ev_get_input(event);
    MultiSocksBuffer *out = multi_socks_ev_get_output(event);

    int in_len = multi_socks_epoll_server_buffer_get_length(in);
    int out_len = multi_socks_epoll_server_buffer_get_length(out);
    LOGD("in len = %d, out len = %d", in_len, out_len);
} */

static void remote_read_cb(MultiSocksEvent *event, void *ctx)
{
    RemoteContext *remote = (RemoteContext *)ctx;
    LOGD("session = %d", remote->session);
    if (remote->tunnel == NULL)
    {
        // wait for tunnel
        multi_socks_epoll_server_event_free(event);
        RemoteContext_free(remote);
        return;
    }

    if (remote->tunnel->status != SOCKS_STATUS_DONE)
    {
        LOGD("wait tunnel to finish auth");
        return;
    }

    MultiSocksBuffer *in = multi_socks_ev_get_input(event);
    size_t len = multi_socks_epoll_server_buffer_get_length(in);
    if (len == 0)
    {
        LOGE("read data len = 0");
        return;
    }

    char data[len];
    if (multi_socks_epoll_server_buffer_copyout(in, data, len) == -1)
    {
        LOGD("copy data failed");
        multi_socks_epoll_server_event_free(event);
        RemoteContext_free(remote);
        return;
    }

    if (send_command(remote, MULTI_SOCKS_CMD_WRITE, data, len) == -1)
    {
        LOGD("send command failed");
        multi_socks_epoll_server_event_free(event);
        RemoteContext_free(remote);
        return;
    }

    multi_socks_epoll_server_buffer_remove(in, len);
}

static void remote_event_cb(MultiSocksEvent *event, int what, void *ctx)
{
    RemoteContext *remote = (RemoteContext *)ctx;
    LOGD("what = %x", what);
    remote->ev = event;
    if (what & MULTI_SOCKS_EV_CONNECT && !(what & MULTI_SOCKS_EV_ERROR))
    {
        remote->status = MSS_REMOTE_STATUS_OK;
        multi_socks_ev_setcb(event, remote_read_cb, NULL, remote_event_cb, ctx);
        // send command

        send_command(remote, MULTI_SOCKS_CMD_CONNECT_RESULT, CONNECT_SUCCESS_RESULT, sizeof(CONNECT_SUCCESS_RESULT));
        return;
    }
    else if (what & MULTI_SOCKS_EV_EOF)
        RemoteContext_free(remote);

    if (remote->status == MSS_REMOTE_STATUS_CONNECTING)
        send_command(remote, MULTI_SOCKS_CMD_CONNECT_RESULT, CONNECT_FAILURE_RESULT, sizeof(CONNECT_FAILURE_RESULT));
}

/***************** Tunnel ******************/
static void tunnel_read_cb(MultiSocksEvent *event, void *ctx)
{
    TunnelContext *tunnel = (TunnelContext *)ctx;

    MultiSocksBuffer *in = multi_socks_ev_get_input(event);

    size_t len = multi_socks_epoll_server_buffer_get_length(in);

    if (len <= 4)
    {
        LOGD("len = %zu; we need read more data", len);
        return;
    }

    char head[4];
    multi_socks_epoll_server_buffer_copyout(in, head, sizeof(head));

    if (head[0] != MULTI_SOCKS_VERSION_1)
    {
        LOGE("bad version: %d, buf len = %zu", head[0], len);
        char buf[len];
        multi_socks_epoll_server_buffer_copyout(in, buf, len);
        hexDump(buf, len, 0);
        multi_socks_epoll_server_event_free(event);
        TunnelContext_free(tunnel);
        return;
    }

    int p_len = read_short(head, 2);
    if (len < p_len)
    {
        LOGD("need read more data");
        return;
    }

    char data[p_len];
    ssize_t copy_result = multi_socks_epoll_server_buffer_copyout(in, data, p_len);

    if (copy_result != p_len)
    {
        LOGE("copy packet failed: need length = %d, result = %d", p_len, copy_result);
    }
    LOGD("read packet full, p_len = %d", p_len);
    char host[data[6] + 1];
    MultiSocksPacket packet;
    bzero(&packet, sizeof(MultiSocksPacket));

    if (data[6] > 0)
    {
        host[sizeof(host) - 1] = 0;
        strncpy(host, data + 7, data[6]);
        packet.host = host;
    }
    packet.p_len = p_len;

    if (!multi_socks_parse_and_verify_checksum(&packet, data))
    {
        LOGE("parse packet failed: packet_len = %d, cmd = %d, sum = %d, d_len = %d", packet.p_len, packet.cmd, packet.sum, packet.d_len);
        multi_socks_epoll_server_event_free(event);
        TunnelContext_free(tunnel);
        return;
    }

    if (multi_socks_epoll_server_buffer_remove(in, p_len) != 0)
    {
        LOGE("multi_socks_epoll_server_buffer_remove failed: in = %p, len = %d", in, p_len);
        TunnelContext_free(tunnel);
        return;
    }

    LOGD("checksum success");
    LOGD("cmd = %x", packet.cmd);

    if (packet.cmd == MULTI_SOCKS_CMD_CONNECT)
    {
        RemoteContext *remote = RemoteContext_new();
        remote->host = strdup(packet.host);
        remote->port = packet.port;

        MultiSocksEvent *rev = multi_socks_epoll_server_connect_hostname(base, socket(AF_INET, SOCK_STREAM, 0), remote->host, remote->port, remote);
        if (rev == NULL)
        {
            RemoteContext_free(remote);
            send_command_to_tunnel(tunnel, &packet, MULTI_SOCKS_CMD_CONNECT_RESULT, CONNECT_FAILURE_RESULT, sizeof(CONNECT_FAILURE_RESULT));
            return;
        }

        remote_sequence++;
        remote->session = remote_sequence;
        remote->tunnel = tunnel;
        remote->sequence = packet.sequence;
        remote->status = MSS_REMOTE_STATUS_CONNECTING;
        remote->ev = rev;
        CSparseArray_put(tunnel->remotes, remote_sequence, remote);
        CSparseArray_put(remotes_map, remote_sequence, remote);

        multi_socks_ev_setcb(rev, NULL, NULL, remote_event_cb, remote);
        LOGD("wait connect response from remote");
        return;
    }
    if (packet.cmd == MULTI_SOCKS_CMD_WRITE)
    {
        RemoteContext *remote = (RemoteContext *)CSparseArray_get(remotes_map, packet.session);
        if (remote == NULL)
        {
            LOGE("find remote failed: session = %d", packet.session);
            send_command_to_tunnel(tunnel, &packet, MULTI_SOCKS_CMD_CLOSE, NULL, 0);
            return;
        }

        MultiSocksBuffer *out = multi_socks_ev_get_output(remote->ev);
        if (multi_socks_epoll_server_buffer_write(out, packet.data, packet.d_len) == -1)
        {
            LOGD("write buffer failed");
            multi_socks_epoll_server_event_free(remote->ev);
            RemoteContext_free(remote);
            return;
        }

        // TODO max buf
    }
    else if (packet.cmd == MULTI_SOCKS_CMD_CLOSE)
    {
        RemoteContext *remote = (RemoteContext *)CSparseArray_remove(remotes_map, packet.session);
        if (remote == NULL || remote->ev == NULL)
        {
            return;
        }
        multi_socks_epoll_server_event_free(remote->ev);
        remote->ev = NULL;
        RemoteContext_free(remote);
    }
    else if (packet.cmd == MULTI_SOCKS_CMD_HEARTBEAT)
    {
        LOGI("session = %x send heartbeat", packet.session);
        send_command_to_tunnel(tunnel, &packet, MULTI_SOCKS_CMD_HEARTBEAT, NULL, 0);
    }

    len = multi_socks_epoll_server_buffer_get_length(in);
    if (len > 4)
        tunnel_read_cb(event, ctx);
}

static void tunnel_event_cb(MultiSocksEvent *event, int what, void *ctx)
{
    LOGD("what = %x", what);
    TunnelContext *tunnel = (TunnelContext *)ctx;
    tunnel->ev = event;
    if (event == NULL || (what & MULTI_SOCKS_EV_ERROR))
    {
        LOGE("tunnel is closed: what = %x", what);
        TunnelContext_free(tunnel);
    }
}

static void negotication_read_cb(MultiSocksEvent *event, void *ctx)
{
    TunnelContext *tunnel = (TunnelContext *)ctx;

    MultiSocksBuffer *out = multi_socks_ev_get_output(event);
    MultiSocksBuffer *in = multi_socks_ev_get_input(event);

    size_t len = multi_socks_epoll_server_buffer_get_length(in);

    if (len <= 4)
    {
        LOGD("wait read more data");
        return;
    }
    char auth_info[len];

    multi_socks_epoll_server_buffer_copyout(in, auth_info, len);

    if (auth_info[0] != MULTI_SOCKS_VERSION_1)
    {
        LOGE("version = %d not supported", auth_info[0]);
        TunnelContext_free(tunnel);
        return;
    }

    if (auth_info[1] != MULTI_SOCKS_AUTH_TYPE_USERNAME_PASSWORD)
    {
        LOGE("version = 1 but auth type (%d) not supported", auth_info[1]);
        TunnelContext_free(tunnel);
        return;
    }

    if (auth_info[2] != 0x00)
    {
        LOGE("RSV (%x) must be 0x00", auth_info[2]);
        TunnelContext_free(tunnel);
        return;
    }

    unsigned char u_len = auth_info[3];

    char username[u_len + 1];
    username[u_len] = '\0';
    if (4 + u_len >= len)
    {
        LOGD("we need wait more data: miss username or password");
        return;
    }

    memcpy(username, auth_info + 4, u_len);
    unsigned char p_len = auth_info[4 + u_len];
    if (4 + u_len + 1 + p_len > len)
    {
        LOGD("we need wait more data: miss password");
        return;
    }

    char password[p_len + 1];
    password[p_len] = '\0';
    memcpy(password, auth_info + 4 + u_len + 1, p_len);

    if (multi_socks_epoll_server_buffer_remove(in, 4 + u_len + 1 + p_len) == -1)
    {
        LOGE("drain auth data failed.");
        TunnelContext_free(tunnel);
        return;
    }

    LOGD("read auth info: u = %s, p = %s", username, password);
    char response[3];
    response[0] = MULTI_SOCKS_VERSION_1;
    response[1] = 0x00;
    response[2] = check_username_password(username, password);

    if (multi_socks_epoll_server_buffer_write(out, response, sizeof(response)) == -1)
    {
        LOGE("write response to server failed: auth result = %d", response[2]);
        TunnelContext_free(tunnel);
        return;
    }
    LOGD("auth success");

    tunnel->status = SOCKS_STATUS_DONE;
    multi_socks_ev_setcb(event, tunnel_read_cb, NULL, tunnel_event_cb, ctx);
}

static void multi_socks_connect_cb(MultiSocksEVListener *l, int fd, struct sockaddr *addr, int addr_len, MultiSocksEvent *event, void *ctx)
{
    LOGD("new connect: fd = %d, address = %s", fd, sockaddr_to_string(addr, NULL, 0));
    TunnelContext *tunnel = TunnelContext_new();
    tunnel->ev = event;
    tunnel->status = 0;
    multi_socks_ev_setcb(event, negotication_read_cb, NULL, tunnel_event_cb, tunnel);

    // struct sockaddr raddr;
    // size_t r_len = sizeof(struct sockaddr);
    // int pr = parse_address("220.181.38.150:443", &raddr, &r_len);
    // if (pr == -1)
    // {
    //     LOGE("parse address failed");
    //     return;
    // }
    // LOGD("address = %s", sockaddr_to_string(&raddr, NULL, 0));
    // multi_socks_epoll_server_connect(base, -1, &raddr, r_len, NULL);
}

void add_auth(char *username, char *password)
{
    if (username == NULL || password == NULL)
    {
        LOGE("bad auth info: u = %s, p = %s", username, password);
        return;
    }
    if (auth_map == NULL)
    {
        auth_map = c_hash_map_new();
        c_hash_map_set_free_cb(auth_map, free);
    }
    LOGD("username = %s, password = %s", username, password);
    c_hash_map_put(auth_map, username, strdup(password));
}

void set_dns_server(const char *host)
{
    if (host == NULL)
        return;

    free(dns_server);
    dns_server = strdup(host);
}

int mss_start(char *ip, int port)
{
    LOGI("start server ip = %s; port = %d", ip, port);
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

    struct sockaddr addr;

    size_t addr_len = sizeof(struct sockaddr);
    if (parse_address(addr_str, &addr, &addr_len) == -1)
    {
        LOGE("parse sockaddr failed");
        return -1;
    }
    base = multi_socks_ev_base_new();
    if (multi_socks_ev_listen(base, multi_socks_connect_cb, -1, &addr, addr_len, base) == NULL)
    {
        return -1;
    }
    if (dns_server == NULL)
        dns_server = "114.114.114.114";

    multi_socks_epoll_server_set_dns_server(base, dns_server);
    remotes_map = CSparseArray_new();

    return multi_socks_ev_loop(base);
}