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

#include "c_array.h"
#include "c_hash_map.h"
#include "multi_socks.h"
#include "libevent_utils_ext.h"
#include "log.h"
#include "socks.h"
#include "clib.h"

#define MULTI_SOCKS_REMOTE_STATUS_CONNECTING 0
#define MULTI_SOCKS_REMOTE_STATUS_OK 1
#define MULTI_SOCKS_REMOTE_STATUS_CLOSED 2

#define MAX_OUTPUT (512 * 1024)

struct event_base *base;
struct evdns_base *dns_base;
struct evconnlistener *listener;

struct multi_socks_context_tunnel;
typedef struct multi_socks_context_tunnel MultiSocksContextTunnel;

static const struct timeval connect_timeout = {60 * 5, 0};

struct multi_socks_context_remote
{
    int status;
    struct bufferevent *bev;

    char *host;
    int port;

    unsigned short sequence; // from client
    unsigned short session;  // server

    MultiSocksContextTunnel *tunnel;
};

typedef struct multi_socks_context_remote MultiSocksContextRemote;

struct multi_socks_packet_data;
typedef struct multi_socks_packet_data MultiSocksPacketData;

struct multi_socks_packet_data
{
    unsigned short len;
    char *data;

    MultiSocksPacketData *next;
};

struct multi_socks_context_tunnel
{
    int status;
    struct bufferevent *bev;
    Array *remotes;
    MultiSocksPacketData *data;
};

static unsigned short remote_sequence = 0;
static MultiSocksContextRemote **remotes_array = NULL;
static CHashMap *auth_map = NULL;

static void tunnel_read_cb(struct bufferevent *bev, void *ctx);
static void tunnel_event_cb(struct bufferevent *bev, short what, void *ctx);
static void remote_event_cb(struct bufferevent *bev, short what, void *ctx);
static void remote_read_cb(struct bufferevent *bev, void *ctx);
static void remote_write_cb(struct bufferevent *bev, void *ctx);

static void free_multi_socks_context_remote(MultiSocksContextRemote *remote)
{
    LOGD("free remote: address = %s:%d; session = %x", remote->host, remote->port, remote->session);
    if (remote->bev)
        bufferevent_free(remote->bev);
    remotes_array[remote->session] = NULL;
    remote->tunnel = NULL;
    free(remote->host);
    free(remote);
}

static void free_multi_socks_context_tunnel(MultiSocksContextTunnel *tunnel)
{
    LOGD("")
    if (tunnel == NULL)
        return;
    if (tunnel->bev != NULL)
        bufferevent_free(tunnel->bev);
    tunnel->bev = NULL;

    Array *array = tunnel->remotes;
    FOR_ARRAY_EACH(array, { // => void* v
        MultiSocksContextRemote *remote = (MultiSocksContextRemote *)v;
        remote->tunnel = NULL;
        LOGD("set tunnel = (null) the remote session is %x", remote->session);
    });
    array_free(array);
    free(array);
    tunnel->remotes = NULL;

    free(tunnel);
}

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

static int send_command_by_packet(MultiSocksPacket *old_packet, MultiSocksContextTunnel *tunnel, int cmd, char *data, int d_len)
{
    LOGD("")
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
    if (bufferevent_write(tunnel->bev, p_data, packet.p_len) == -1)
    {
        free_multi_socks_context_tunnel(tunnel);
        return -1;
    }
    return 0;
}

static int send_command(MultiSocksContextRemote *remote, int cmd, char *data, int d_len)
{
    LOGD("cmd = %x, data len = %d", cmd, d_len);
    if (remote->tunnel == NULL || remote->tunnel->bev == NULL)
    {
        LOGI("tunnel is closed.")
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
    packet.p_len = 7 + strlen(packet.host) + 2 + 2 + 2 + 2 + d_len;

    char p_data[packet.p_len];
    bzero(p_data, sizeof(p_data));
    multi_socks_checksum_and_pack(&packet, p_data);
    size_t out_len = evbuffer_get_length(bufferevent_get_output(remote->tunnel->bev));
    if (out_len > 0)
    {
        MultiSocksPacketData *packet_data = (MultiSocksPacketData *)malloc(sizeof(MultiSocksPacketData));
        packet_data->len = packet.p_len;
        packet_data->data = (char *)malloc(packet.p_len);
        memcpy(packet_data->data, p_data, packet_data->len);
        if (remote->tunnel->data == NULL)
            remote->tunnel->data = packet_data;
        else
        {
            MultiSocksPacketData *node = remote->tunnel->data;
            while (node)
            {
                if (node->next == NULL)
                {
                    node->next = packet_data;
                    break;
                }
                node = node->next;
            }
        }

        LOGD("save data to tunnel array: len = %d", packet_data->len);
        return 0;
    }
    if (bufferevent_write(remote->tunnel->bev, p_data, packet.p_len) == -1)
    {
        LOGE("write data to tunnel failed.")
        free_multi_socks_context_tunnel(remote->tunnel);
        return -1;
    }
    LOGD("packet ready send to tunnel: outlen = %zu", out_len);

    return 0;
}

static void tunnel_write_cb(struct bufferevent *bev, void *ctx)
{
    MultiSocksContextTunnel *tunnel = (MultiSocksContextTunnel *)ctx;

    EV_BUF *out = bufferevent_get_output(bev);
    size_t out_len = evbuffer_get_length(out);
    LOGD("output len = %zu", out_len);

    if (out_len == 0 && tunnel->data != NULL)
    {
        MultiSocksPacketData *data = tunnel->data;
        LOGD("write data from list: data len = %d", data->len);
        if (data->len == 0 || data->data == NULL || bufferevent_write(bev, data->data, data->len) == -1)
        {
            LOGD("write data to tunnel failed");
            free_multi_socks_context_tunnel(tunnel);
            return;
        }
        tunnel->data = data->next;
        free(data->data);
        free(data);
    }

    tunnel_read_cb(bev, ctx);
}

static void remote_write_cb(struct bufferevent *bev, void *ctx)
{
    EV_BUF *out = bufferevent_get_output(bev);
    LOGD("output len = %zu", evbuffer_get_length(out));
}

static void remote_read_cb(struct bufferevent *bev, void *ctx)
{
    MultiSocksContextRemote *remote = (MultiSocksContextRemote *)ctx;
    if (remote->tunnel == NULL || remote->tunnel->status != MULTI_SOCKS_REMOTE_STATUS_OK)
    {
        LOGD("wait for a new tunnel");
        return;
    }

    EV_BUF *in = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(in);
    LOGD("remote (%s:%d) read data(len = %zu)", remote->host, remote->port, len);
    char data[len];
    if (evbuffer_copyout(in, data, len) != len)
    {
        LOGE("read data from remote failed");
        send_command(remote, MULTI_SOCKS_CMD_CLOSE, NULL, len);
        free_multi_socks_context_remote(remote);
        return;
    }

    if (send_command(remote, MULTI_SOCKS_CMD_WRITE, data, len) == -1)
    {
        LOGE("tunnel is closed, we should wait a little time");
        return;
    }
    if (evbuffer_drain(in, len) == -1)
    {
        LOGE("drain data failed");
        send_command(remote, MULTI_SOCKS_CMD_CLOSE, NULL, len);
        free_multi_socks_context_remote(remote);
        return;
    }
}

static void remote_drain_write_cb(struct bufferevent *bev, void *ctx)
{
    LOGD("")
    MultiSocksContextRemote *remote = (MultiSocksContextRemote *)ctx;
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    bufferevent_setcb(bev, remote_read_cb, remote_write_cb, remote_event_cb, ctx);
    send_command(remote, MULTI_SOCKS_CMD_FREE_DRAIN, NULL, 0);
}

static void tunnel_read_cb(struct bufferevent *bev, void *ctx)
{
    LOGD("")
    MultiSocksContextTunnel *tunnel = (MultiSocksContextTunnel *)ctx;
    EV_BUF *in = bufferevent_get_input(bev);

    int len = evbuffer_get_length(in);

    if (len <= 4)
    {
        LOGD("len = %d; we need read more data", len);
        return;
    }

    char head[4];
    if (evbuffer_copyout(in, head, sizeof(head)) != 4)
    {
        LOGD("copy packet head failed")
        return;
    }

    if (head[0] != MULTI_SOCKS_VERSION_1)
    {
        free_multi_socks_context_tunnel(tunnel);
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
        free_multi_socks_context_tunnel(tunnel);
        return;
    }

    LOGD("read packet full, p_len = %d", p_len);
    MultiSocksPacket packet;
    bzero(&packet, sizeof(MultiSocksPacket));
    packet.p_len = p_len;
    if (!multi_socks_parse_and_verify_checksum(&packet, data))
    {
        LOGE("parse packet failed: packet_len = %d, cmd = %d, sum = %d, d_len = %d", packet.p_len, packet.cmd, packet.sum, packet.d_len);
        free_multi_socks_context_tunnel(tunnel);
        return;
    }
    if (evbuffer_drain(in, p_len) == -1)
    {
        LOGE("drain data failed");
        free_multi_socks_context_tunnel(tunnel);
        return;
    }
    LOGD("checksum success");
    LOGD("cmd = %x", packet.cmd);

    if (packet.cmd == MULTI_SOCKS_CMD_CONNECT)
    {
        MultiSocksContextRemote *remote = (MultiSocksContextRemote *)malloc(sizeof(MultiSocksContextRemote));
        bzero(remote, sizeof(MultiSocksContextRemote));
        remote->host = packet.host;
        remote->port = packet.port;

        remote->bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
        if (remote->bev == NULL)
        {
            free(packet.host);
            free_multi_socks_context_remote(remote);
            return;
        }

        char *address = NULL;
        asprintf(&address, "%s:%d", remote->host, remote->port);
        LOGD("connect to remote (%s) fd = %d", address, bufferevent_getfd(remote->bev));
        struct sockaddr addr;
        bzero(&addr, sizeof(struct sockaddr));

        int outlen = 0;
        int pr = parse_address(address, &addr, &outlen);
        // int pr = evutil_parse_sockaddr_port(address, &addr, &outlen);
        LOGD("parse address result = %d, addr = %s, outlen = %d", pr, sockaddr_to_string(&addr, NULL, 0), outlen);
        free(address);
        if (bufferevent_socket_connect(remote->bev, &addr, outlen) == -1)
        {
            LOGI("connect to %s:%d failed", remote->host, remote->port);
            free(packet.host);
            remote->host = NULL;
            free_multi_socks_context_remote(remote);
            return;
        }
        // if (bufferevent_socket_connect_hostname(remote->bev, dns_base, AF_UNSPEC, remote->host, remote->port) == -1)
        // {
        //     free(packet.host);
        //     LOGI("connect to %s:%d failed", remote->host, remote->port);
        //     free_multi_socks_context_remote(remote);
        //     return;
        // }
        remote->session = remote_sequence;
        remote->tunnel = tunnel;
        remote->sequence = packet.sequence;
        remote->status = MULTI_SOCKS_REMOTE_STATUS_CONNECTING;
        array_add(tunnel->remotes, remote);

        remote_sequence++;

        remotes_array[remote->session] = remote;
        LOGD("session(%x) => %p", remote->session, remote);

        bufferevent_setcb(remote->bev, NULL, NULL, remote_event_cb, remote);
        // bufferevent_set_timeouts(remote->bev, &connect_timeout, &connect_timeout);
        LOGD("wait connect response from remote");
    }
    else if (packet.cmd == MULTI_SOCKS_CMD_CLOSE)
    {
        MultiSocksContextRemote *remote = remotes_array[packet.session];
        if (remote == NULL)
            return;

        free_multi_socks_context_remote(remote);
    }
    else if (packet.cmd == MULTI_SOCKS_CMD_WRITE)
    {
        MultiSocksContextRemote *remote = remotes_array[packet.session];
        if (remote == NULL)
        {
            send_command_by_packet(&packet, tunnel, MULTI_SOCKS_CMD_CLOSE, NULL, 0);
            return;
        }
        if (bufferevent_write(remote->bev, packet.data, packet.d_len) == -1)
        {
            LOGE("write data (d = %d) to remote failed", packet.p_len);
            send_command(remote, MULTI_SOCKS_CMD_CLOSE, NULL, 0);
            free_multi_socks_context_remote(remote);
            return;
        }

        LOGD("data (len = %d) ready send to remote(%s:%d)", packet.d_len, remote->host, remote->port);
        EV_BUF *out = bufferevent_get_output(remote->bev);
        if (evbuffer_get_length(out) > MAX_OUTPUT)
        {
            LOGD("remote(%s:%d) start drain", remote->host, remote->port);
            send_command(remote, MULTI_SOCKS_CMD_DRAIN, NULL, 0);
            bufferevent_setwatermark(remote->bev, EV_WRITE, MAX_OUTPUT / 2, MAX_OUTPUT);
            bufferevent_setcb(remote->bev, remote_read_cb, remote_drain_write_cb, remote_event_cb, remote);
        }
    }
    else if (packet.cmd == MULTI_SOCKS_CMD_DRAIN)
    {
        MultiSocksContextRemote *remote = remotes_array[packet.session];
        if (remote == NULL)
        {
            send_command_by_packet(&packet, tunnel, MULTI_SOCKS_CMD_CLOSE, NULL, 0);
            return;
        }
        LOGD("remote(%s:%d) read disabled", remote->host, remote->port)
        bufferevent_disable(remote->bev, EV_READ);
    }
    else if (packet.cmd == MULTI_SOCKS_CMD_FREE_DRAIN)
    {
        MultiSocksContextRemote *remote = remotes_array[packet.session];
        if (remote == NULL)
        {
            send_command_by_packet(&packet, tunnel, MULTI_SOCKS_CMD_CLOSE, NULL, 0);
            return;
        }
        bufferevent_enable(remote->bev, EV_READ);
    }
    else if (packet.cmd == MULTI_SOCKS_CMD_HEARTBEAT)
    {
        LOGI("session = %x send heartbeat", packet.session);
    }

    tunnel_read_cb(bev, ctx);
}

static void negotication_read_cb(struct bufferevent *bev, void *ctx)
{
    LOGD("");
    MultiSocksContextTunnel *tunnel = (MultiSocksContextTunnel *)ctx;
    EV_BUF *in = bufferevent_get_input(tunnel->bev);
    size_t len = evbuffer_get_length(in);
    if (len <= 4)
    {
        LOGD("wait read more data");
        return;
    }
    char auth_info[len];

    if (evbuffer_copyout(in, auth_info, len) != len)
    {
        LOGE("copy out negotication header failed.");
        free_multi_socks_context_tunnel(tunnel);
        return;
    }

    if (auth_info[0] != MULTI_SOCKS_VERSION_1)
    {
        LOGE("version = %d not supported", auth_info[0]);
        free_multi_socks_context_tunnel(tunnel);
        return;
    }

    if (auth_info[1] != MULTI_SOCKS_AUTH_TYPE_USERNAME_PASSWORD)
    {
        LOGE("version = 1 but auth type (%d) not supported", auth_info[1]);
        free_multi_socks_context_tunnel(tunnel);
        return;
    }

    if (auth_info[2] != 0x00)
    {
        LOGE("RSV (%x) must be 0x00", auth_info[2]);
        free_multi_socks_context_tunnel(tunnel);
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

    if (evbuffer_drain(in, 4 + u_len + 1 + p_len) == -1)
    {
        LOGE("drain auth data failed.");
        free_multi_socks_context_tunnel(tunnel);
        return;
    }

    LOGD("read auth info: u = %s, p = %s", username, password);
    char response[3];
    response[0] = MULTI_SOCKS_VERSION_1;
    response[1] = 0x00;
    response[2] = check_username_password(username, password);

    if (bufferevent_write(bev, response, sizeof(response)) == -1)
    {
        LOGE("write response to server failed: auth result = %d", response[2]);
        free_multi_socks_context_tunnel(tunnel);
        return;
    }

    tunnel->status = MULTI_SOCKS_REMOTE_STATUS_OK;
    bufferevent_setcb(bev, tunnel_read_cb, tunnel_write_cb, tunnel_event_cb, tunnel);
}
static void remote_event_cb(struct bufferevent *bev, short what, void *ctx)
{
    MultiSocksContextRemote *remote = (MultiSocksContextRemote *)ctx;
    LOGD("address = %s:%d, waht = %x", remote->host, remote->port, what);
    if (what & (BEV_EVENT_READING | BEV_EVENT_WRITING | BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT))
    {
        if (remote->status == MULTI_SOCKS_REMOTE_STATUS_CONNECTING)
        {
            LOGD("connect to remote failed")
            char result[1];
            result[0] = 0xff;
            send_command(remote, MULTI_SOCKS_CMD_CONNECT_RESULT, result, 1);
        }
        else
        {
            LOGD("remote closed")
            send_command(remote, MULTI_SOCKS_CMD_CLOSE, NULL, 0);
        }
    }
    else if (what & BEV_EVENT_CONNECTED)
    {
        // connect to remote, send response to client
        LOGD("remote sequence = %d, session = %x ", remote->sequence, remote->session)
        remote->status = MULTI_SOCKS_REMOTE_STATUS_OK;
        char result[1];
        result[0] = 0;
        bufferevent_setcb(bev, remote_read_cb, remote_write_cb, remote_event_cb, remote);
        bufferevent_enable(bev, EV_READ | EV_WRITE);

        send_command(remote, MULTI_SOCKS_CMD_CONNECT_RESULT, result, 1);
    }
}

static void tunnel_event_cb(struct bufferevent *bev, short what, void *ctx)
{
    LOGD("what = %x", what);
    if (what & (BEV_EVENT_READING | BEV_EVENT_WRITING | BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT))
    {
        MultiSocksContextTunnel *tunnel = (MultiSocksContextTunnel *)ctx;
        free_multi_socks_context_tunnel(tunnel);
    }
}

static void multi_listener_cb(struct evconnlistener *l, int fd, struct sockaddr *addr, int socklen, void *ctx)
{
    LOGD("new tunnel connected; fd = %d, address = %s", fd, sockaddr_to_string(addr, NULL, 0));
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    MultiSocksContextTunnel *tunnel = (MultiSocksContextTunnel *)malloc(sizeof(MultiSocksContextTunnel));
    bzero(tunnel, sizeof(MultiSocksContextTunnel));

    tunnel->bev = bev;
    tunnel->remotes = (Array *)malloc(sizeof(Array));
    array_init(tunnel->remotes);

    bufferevent_setcb(bev, negotication_read_cb, tunnel_write_cb, tunnel_event_cb, tunnel);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    // bufferevent_set_timeouts(bev, &connect_timeout, &connect_timeout);
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
        auth_map = (CHashMap *)malloc(sizeof(CHashMap));
        c_hash_map_init(auth_map);
        auth_map->free_cb = free;
    }
    LOGD("username = %s, password = %s", username, password);
    c_hash_map_put(auth_map, username, strdup(password));
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

    struct sockaddr_storage addr;

    int addr_len = sizeof(addr);
    if (evutil_parse_sockaddr_port(addr_str, (struct sockaddr *)&addr, &addr_len))
    {
        LOGE("parse sockaddr failed");
        return -1;
    }

    base = event_base_new();
    if (base == NULL)
    {
        LOGE("event_base_new: failed, errno = %d; %s", errno, strerror(errno));
        return -1;
    }

    remotes_array = (MultiSocksContextRemote **)malloc(65536);
    bzero(remotes_array, 65536);

    dns_base = evdns_base_new(base, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
    evdns_base_nameserver_ip_add(dns_base, "114.114.114.114");

    listener = evconnlistener_new_bind(base, multi_listener_cb, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE, -1, (struct sockaddr *)&addr, addr_len);

    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);
    return 0;
}