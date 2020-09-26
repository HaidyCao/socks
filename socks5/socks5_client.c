#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdbool.h>
#include <strings.h>

#include "socks5_client.h"
#include "../log.h"
#include "../lib/clib.h"
#include "../dependencies/kcp-1.7/ikcp.h"
#include "c_hex_utils.h"

#define CLIENT_MAX_SUPPORT_METHOD_COUNT 4
#define KCP_KEY_LEN 2

static char *auth_username = NULL;
static char *auth_password = NULL;

static bool server_ssl = false;
static char *server_host = NULL;
static u_short server_port = 0;

static int use_kcp = 0;

static void socks5_client_event_cb(MultiSocksEvent *ev, int what, void *ctx);

const char *socks5_client_get_rep_string(int rep) {
    if (rep == SOCKS5_REPLY_SUCCEEDED) {
        return "succeeded";
    } else if (rep == SOCKS5_REPLY_GENERAL_SOCKS_SERVER_FAILURE) {
        return "general SOCKS server failure";
    } else if (rep == SOCKS5_REPLY_CONNECTION_NOT_ALLOWED_BY_RULESET) {
        return "connection not allowed by ruleset";
    } else if (rep == SOCKS5_REPLY_NETWORK_UNREACHABLE) {
        return "Network unreachable";
    } else if (rep == SOCKS5_REPLY_HOST_UNREACHABLE) {
        return "Host unreachable";
    } else if (rep == SOCKS5_REPLY_CONNECT_REFUSED) {
        return "Connection refused";
    } else if (rep == SOCKS5_REPLY_TTL_EXPIRED) {
        return "TTL expired";
    } else if (rep == SOCKS5_REPLY_COMMAND_NOT_SUPPORTED) {
        return "Command not supported";
    } else if (rep == SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED) {
        return "Address type not supported";
    } else if (rep == SOCKS5_REPLY_EXT_AUTH_FAILED) {
        return "Auth Failed";
    } else {
        return "unassigned";
    }
}

typedef struct {
    MultiSocksEvent *ev;

    char *remote_host;
    uint16_t remote_port;
    socks5_client_auth_cb auth_cb;
    void *ctx;
    int use_kcp;
} Client;

static Client *Client_new(MultiSocksEvent *ev, char *host, uint16_t port, socks5_client_auth_cb cb, void *ctx) {
    Client *c = malloc(sizeof(Client));
    c->ev = ev;
    c->remote_host = strdup(host);
    c->remote_port = port;
    c->auth_cb = cb;
    c->ctx = ctx;
    c->use_kcp = 0;
    return c;
}

static void Client_free(Client *client) {
    if (client == NULL)
        return;

    if (client->ev != NULL)
        multi_socks_epoll_server_event_free(client->ev);
    client->ev = NULL;
    free(client->remote_host);
    free(client);
}

typedef struct {
    MultiSocksEvent *ev;
    socks5_client_remote_read_cb cb;
    void *ctx;

    IUINT32 next_time;
    ikcpcb *kcp;
    MultiSocksEvent *remote;
} RemoteTransfer;

static RemoteTransfer *
RemoteTransfer_new(MultiSocksEvent *ev, socks5_client_remote_read_cb cb, void *ctx) {
    RemoteTransfer *transfer = calloc(1, sizeof(RemoteTransfer));
    transfer->ev = ev;
    transfer->cb = cb;
    transfer->ctx = ctx;

    return transfer;
}

static void
RemoteTransfer_free(RemoteTransfer *transfer) {
    if (transfer == NULL)
        return;
    LOGD("free: transfer = %p, ev = %p", transfer, transfer->ev);
    if (transfer->ev) {
        multi_socks_epoll_server_event_free(transfer->ev);
        transfer->ev = NULL;
    }
    if (transfer->remote) {
        multi_socks_epoll_server_event_free(transfer->remote);
        transfer->remote = NULL;
    }

    if (transfer->kcp) {
        ikcp_release(transfer->kcp);
        transfer->kcp = NULL;
    }

    free(transfer);
}

static void
socks5_client_udp_remote_read(MultiSocksEvent *ev, MultiSocksBuffer *buffer, struct sockaddr *addr, socklen_t addr_len,
                              void *ctx) {
    LOGD("remote read");
    RemoteTransfer *transfer = ctx;
    size_t len = multi_socks_epoll_server_buffer_get_length(buffer);
    char buf[len];

    multi_socks_epoll_server_buffer_copyout(buffer, buf, len);
    multi_socks_epoll_server_buffer_remove(buffer, len);

    LOGD("read len = %zu from %s, kcp = %p", len, sockaddr_to_string(addr, NULL, 0), transfer->kcp);
    hexDump(buf, len, 0);

    transfer->next_time = 0;
    int input_result = ikcp_input(transfer->kcp, buf, len);
    LOGD("ikcp_input = %d", input_result);

    int r_len;
    while (1) {
        int p_size = ikcp_peeksize(transfer->kcp);
        if (p_size < 0)
            break;

        char p_buf[p_size];
        r_len = ikcp_recv(transfer->kcp, p_buf, p_size);
        LOGD("ikcp_recv = %d", r_len);
        if (r_len <= 0)
            break;
        if (transfer->cb)
            transfer->cb(ev, p_buf, r_len, transfer->ctx);
    }
}

static void
socks5_client_remote_read(MultiSocksEvent *ev, void *ctx) {
    LOGD("remote read");
    RemoteTransfer *transfer = ctx;
    MultiSocksBuffer *in = multi_socks_ev_get_input(ev);
    size_t len = multi_socks_epoll_server_buffer_get_length(in);
    char buf[len];

    multi_socks_epoll_server_buffer_copyout(in, buf, len);
    multi_socks_epoll_server_buffer_remove(in, len);

    LOGD("read len = %zu", len);

    if (transfer->cb)
        transfer->cb(ev, buf, len, transfer->ctx);
}

static void
socks5_client_remote_event(MultiSocksEvent *ev, int what, void *ctx) {
    LOGD("what = %x", what);
    RemoteTransfer *transfer = ctx;
    if (ev != NULL && ev != transfer->ev) {
        transfer->remote = ev;
    } else {
        transfer->ev = ev;
    }

    // on remote close
    if (transfer->cb)
        transfer->cb(ev, NULL, 0, transfer->ctx);

    transfer->ctx = NULL;
    RemoteTransfer_free(transfer);
}

int
socks5_client_write_data_to_remote(MultiSocksEvent *remote, char *buf, size_t len) {
    LOGD("data len = %zu", len);
    if (buf == NULL)
        return -1;
    RemoteTransfer *transfer = multi_socks_epoll_server_event_get_ctx(remote);
    if (transfer->kcp) {
        transfer->next_time = 0;

        size_t mtu = transfer->kcp->mtu;
        size_t left = len;
        while (1) {
            if (left <= mtu) {
                ikcp_send(transfer->kcp, buf, left);
                break;
            } else {
                ikcp_send(transfer->kcp, buf, mtu);
                left -= mtu;
                buf += mtu;
            }
        }

        return len;
    }

    LOGD("write data to remote: len = %zu", len);
    MultiSocksBuffer *out = multi_socks_ev_get_output(remote);
    multi_socks_epoll_server_buffer_write(out, buf, len);
    return len;
}

static int remote_transfer_kcp_out(const char *buf, int len, ikcpcb *kcp, void *user) {
    RemoteTransfer *transfer = user;
    MultiSocksBuffer *out = multi_socks_ev_get_output(transfer->ev);
    multi_socks_epoll_server_buffer_write(out, (char *) buf, len);
    return len;
}

/* get system time */
static void itimeofday(long *sec, long *usec) {
    struct timeval time;
    gettimeofday(&time, NULL);
    if (sec) *sec = time.tv_sec;
    if (usec) *usec = time.tv_usec;
}

/* get clock in millisecond 64 */
static IUINT64 iclock64(void) {
    long s, u;
    IUINT64 value;
    itimeofday(&s, &u);
    value = ((IUINT64) s) * 1000 + (u / 1000);
    return value;
}

static IUINT32 iclock() {
    return (IUINT32) (iclock64() & 0xfffffffful);
}

static void remote_transfer_kcp_timer_cb(MultiSocksTimer *timer, void *ctx) {
//    LOGD("kcp update timer");
    RemoteTransfer *transfer = ctx;
    if (ctx == NULL || transfer->kcp == NULL) {
        multi_socks_epoll_server_stop_timer(timer);
        return;
    }

    IUINT32 current = iclock();

    if (transfer->next_time <= current)
        ikcp_update(transfer->kcp, current);

    IUINT32 next = ikcp_check(transfer->kcp, current);
    transfer->next_time = next;
}

int
socks5_client_set_remote_read_cb(MultiSocksEvent *remote, char *bind_addr, u_short bind_port, u_short kcp_key,
                                 socks5_client_remote_read_cb cb, void *ctx) {
    if (remote == NULL) {
        LOGE("remote is NULL");
        return -1;
    }

    RemoteTransfer *transfer = RemoteTransfer_new(remote, cb, ctx);
    if (use_kcp && kcp_key != 0) {
        transfer->ev = NULL;
        transfer->kcp = ikcp_create(kcp_key, transfer);
        transfer->remote = remote;

        ikcp_setoutput(transfer->kcp, remote_transfer_kcp_out);

        MultiSocksEvent *kcp_ev = multi_socks_epoll_server_udp_hostname(multi_socks_epoll_server_event_get_base(remote),
                                                                        -1, bind_addr, bind_port, NULL);
        if (kcp_ev == NULL) {
            LOGE("bind udp failed");
            if (cb != NULL) {
                cb(NULL, NULL, 0, ctx);
            }
            RemoteTransfer_free(transfer);
            return -1;
        }
        transfer->ev = kcp_ev;
        multi_socks_ev_udp_setcb(kcp_ev, socks5_client_udp_remote_read, NULL, socks5_client_remote_event, transfer);
//        multi_socks
        multi_socks_ev_setcb(remote, NULL, NULL, socks5_client_remote_event, transfer);

        multi_socks_epoll_server_event_set_timer(kcp_ev, 10, remote_transfer_kcp_timer_cb, transfer);
        return 0;
    }
    multi_socks_ev_setcb(remote, socks5_client_remote_read, NULL, socks5_client_remote_event, transfer);
    return 0;
}

#define TRANSFER_TYPE_LOCAL 0
#define TRANSFER_TYPE_KCP 1
#define TRANSFER_TYPE_REMOTE 2

typedef struct {
    MultiSocksEvent *ev;
    void *partner; /* TransferContext */
    ikcpcb *kcp;
    int kcp_input_send_flag;

    socks5_client_transfer_data_close_cb cb;

    int type;
    void *ctx;
} TransferContext;

static void TransferContext_free(TransferContext *transfer) {
    if (transfer->type == TRANSFER_TYPE_REMOTE && transfer->ctx) {
        TransferContext *kcp = transfer->ctx;
        kcp->ctx = NULL;
        TransferContext_free(kcp);
        transfer->ctx = NULL;
    } else if (transfer->type == TRANSFER_TYPE_KCP && transfer->ctx) {
        TransferContext *remote = transfer->ctx;
        remote->ctx = NULL;
        TransferContext_free(remote);
        transfer->ctx = NULL;
    }

    if (transfer->partner) {
        TransferContext *partner = transfer->partner;
        partner->partner = NULL;
        TransferContext_free(partner);
    }

    if (transfer->cb)
        transfer->cb(transfer->ev, transfer->ctx);

    if (transfer->ev) {
        multi_socks_epoll_server_event_free(transfer->ev);
        transfer->ev = NULL;
    }
    free(transfer);
}

static TransferContext *TransferContext_new(MultiSocksEvent *ev, void *ctx, int type) {
    TransferContext *transfer = calloc(1, sizeof(TransferContext));
    transfer->ev = ev;
    transfer->ctx = ctx;
    transfer->type = type;

    return transfer;
}

static void
socks5_client_transfer_udp_read_cb(MultiSocksEvent *ev, MultiSocksBuffer *buffer, struct sockaddr *addr,
                                   socklen_t addr_len, void *ctx) {
    TransferContext *transfer = ctx;
    size_t len = multi_socks_epoll_server_buffer_get_length(buffer);
    char buf[len];

    multi_socks_epoll_server_buffer_copyout(buffer, buf, len);
    multi_socks_epoll_server_buffer_remove(buffer, len);
    transfer->kcp_input_send_flag = 1;

    ikcp_input(transfer->kcp, buf, len);
    int r_len;
    while ((r_len = ikcp_recv(transfer->kcp, buf, len)) > 0) {
        TransferContext *local = transfer->partner;
        MultiSocksBuffer *out = multi_socks_ev_get_output(local->ev);
        multi_socks_epoll_server_buffer_write(out, buf, r_len);
    }
}

static void socks5_client_transfer_read_cb(MultiSocksEvent *ev, void *ctx) {
    LOGD("transfer data");
    TransferContext *transfer = ctx;
    MultiSocksBuffer *in = multi_socks_ev_get_input(ev);

    if (use_kcp) {
        size_t len = multi_socks_epoll_server_buffer_get_length(in);
        char buf[len];

        multi_socks_epoll_server_buffer_copyout(in, buf, len);
        multi_socks_epoll_server_buffer_remove(in, len);
        transfer->kcp_input_send_flag = 1;

        TransferContext *kcp_transfer = transfer->partner;
        ikcp_send(kcp_transfer->kcp, buf, len);
        return;
    }

    TransferContext *partner = transfer->partner;
    MultiSocksBuffer *out = multi_socks_ev_get_output(partner->ev);
    multi_socks_epoll_server_buffer_add_buffer(out, in);
}

static void socks5_client_transfer_event_cb(MultiSocksEvent *ev, int what, void *ctx) {
    LOGD("what = %x", what);
    TransferContext *transfer = ctx;
    transfer->ev = ev;
    TransferContext_free(transfer);
}

static int kcp_out(const char *buf, int len, ikcpcb *kcp, void *user) {
    TransferContext *transfer = user;
    if (transfer->ev == NULL)
        return -1;

    MultiSocksBuffer *out = multi_socks_ev_get_output(transfer->ev);
    multi_socks_epoll_server_buffer_write(out, (char *) buf, len);
    return len;
}

static void kcp_timer_cb(MultiSocksTimer *timer, void *ctx) {
    LOGD("kcp update timer");
    TransferContext *transfer = ctx;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    IUINT32 current = (IUINT32) (((uint) tv.tv_sec * 1000 + tv.tv_usec / 1000) & 0xfffffffful);

    if (transfer->kcp_input_send_flag)
        ikcp_update(transfer->kcp, current);
    transfer->kcp_input_send_flag = 0;

    IUINT32 next = ikcp_check(transfer->kcp, current);
    multi_socks_epoll_server_event_set_timer_oneshot(transfer->ev, next - current, kcp_timer_cb, ctx);
}

int
socks5_client_transfer_data(MultiSocksEvent *local, MultiSocksEvent *remote, char *bind_addr, u_short bind_port,
                            u_short kcp_key, socks5_client_transfer_data_close_cb cb, void *ctx) {
    TransferContext *local_transfer = TransferContext_new(local, ctx, TRANSFER_TYPE_LOCAL);
    local_transfer->cb = cb;

    multi_socks_ev_setcb(local, socks5_client_transfer_read_cb, NULL, socks5_client_transfer_event_cb, local_transfer);
    if (use_kcp) {
        MultiSocksEvent *kcp_ev = multi_socks_epoll_server_udp_hostname(multi_socks_epoll_server_event_get_base(local),
                                                                        -1, bind_addr, bind_port, NULL);

        TransferContext *kcp_transfer = TransferContext_new(kcp_ev, NULL, TRANSFER_TYPE_KCP);
        multi_socks_ev_udp_setcb(kcp_ev, socks5_client_transfer_udp_read_cb, NULL, socks5_client_transfer_event_cb,
                                 kcp_transfer);

        local_transfer->partner = kcp_ev;

        TransferContext *remote_transfer = TransferContext_new(remote, kcp_transfer, TRANSFER_TYPE_REMOTE);
        kcp_transfer->type = TRANSFER_TYPE_KCP;
        kcp_transfer->ctx = remote_transfer;
        kcp_transfer->partner = local_transfer;
        kcp_transfer->kcp = ikcp_create(kcp_key, kcp_transfer);
        ikcp_setoutput(kcp_transfer->kcp, kcp_out);

        remote_transfer->type = TRANSFER_TYPE_REMOTE;
        remote_transfer->partner = NULL;

        // kcp set timer
        multi_socks_epoll_server_event_set_timer(kcp_ev, 10, kcp_timer_cb, kcp_transfer);

        multi_socks_ev_setcb(remote, NULL, NULL, socks5_client_transfer_event_cb, kcp_transfer);
    } else {
        TransferContext *remote_transfer = TransferContext_new(remote, NULL, TRANSFER_TYPE_REMOTE);
        remote_transfer->partner = local_transfer;
        local_transfer->partner = remote_transfer;
        multi_socks_ev_setcb(remote, socks5_client_transfer_read_cb, NULL, socks5_client_transfer_event_cb,
                             remote_transfer);
    }
    return 0;
}

static void socks5_client_connect_result_cb(MultiSocksEvent *ev, void *ctx) {
    LOGD("connect result");
    Client *client = ctx;
    MultiSocksBuffer *in = multi_socks_ev_get_input(ev);
    size_t len = multi_socks_epoll_server_buffer_get_length(in);

    if (len <= SOCKS5_CONN_HEADER_LEN) {
        LOGD("need read more data");
        return;
    }

    char buf[len];
    multi_socks_epoll_server_buffer_copyout(in, buf, sizeof(buf));
    if (buf[0] != SOCKS5_VERSION) {
        LOGD("bad version");
        if (client->auth_cb) client->auth_cb(NULL, -1, NULL, 0, 0, client->ctx);
        Client_free(client);
        return;
    }
    hexDump(buf, len, 0);

    if (buf[1] != SOCKS5_REPLY_SUCCEEDED) {
        LOGD("connect failed: %s", socks5_client_get_rep_string(buf[1]));
        if (client->auth_cb) client->auth_cb(NULL, buf[1], NULL, 0, 0, client->ctx);
        Client_free(client);
        return;
    }
    LOGD("connect success");

    if (buf[2] != 0x00) {
        LOGD("bad RSV");
        if (client->auth_cb) client->auth_cb(NULL, -1, NULL, 0, 0, client->ctx);
        Client_free(client);
        return;
    }

    int a_type = buf[3];
    LOGD("resp address type = %d", a_type);

    char host[MAX_DOMAIN_LEN];
    bzero(host, sizeof(host));
    u_short port;

    size_t ext_len = use_kcp ? KCP_KEY_LEN : 0;
    u_short kcp_key = 0;
    if (a_type == SOCKS5_ATYPE_IPV4) {
        if (len < SOCKS5_CONN_HEADER_LEN + IPV4_LEN + ext_len + PORT_LEN) {
            LOGD("need read more data");
            return;
        }
        sprintf(host, "%d.%d.%d.%d", (int) buf[SOCKS5_CONN_HEADER_LEN], (int) buf[SOCKS5_CONN_HEADER_LEN + 1],
                (int) buf[SOCKS5_CONN_HEADER_LEN + 2], (int) buf[SOCKS5_CONN_HEADER_LEN + 3]);
        if (client->use_kcp) {
            kcp_key = ntohs_by_data(buf, SOCKS5_CONN_HEADER_LEN + IPV4_LEN);
        }
        port = ntohs_by_data(buf, SOCKS5_CONN_HEADER_LEN + IPV4_LEN + ext_len);
        multi_socks_epoll_server_buffer_remove(in, SOCKS5_CONN_HEADER_LEN + IPV4_LEN + ext_len + PORT_LEN);
    } else if (a_type == SOCKS5_ATYPE_IPV6) {
        if (len < SOCKS5_CONN_HEADER_LEN + IPV6_LEN + PORT_LEN) {
            LOGD("need read more data");
            return;
        }

        char *ipv6 = ipv6_to_string(buf + SOCKS5_CONN_HEADER_LEN);
        memcpy(host, ipv6, strlen(ipv6));
        free(ipv6);
        if (use_kcp) {
            kcp_key = ntohs_by_data(buf, SOCKS5_CONN_HEADER_LEN + IPV4_LEN);
        }
        port = ntohs_by_data(buf, SOCKS5_CONN_HEADER_LEN + IPV6_LEN + ext_len);
        multi_socks_epoll_server_buffer_remove(in, SOCKS5_CONN_HEADER_LEN + IPV6_LEN + ext_len + PORT_LEN);
    } else {
        u_char host_len = buf[SOCKS5_CONN_HEADER_LEN];
        if (len < SOCKS5_CONN_HEADER_LEN + 1 + host_len + PORT_LEN) {
            LOGD("need read more data");
            return;
        }

        memcpy(host, buf + SOCKS5_CONN_HEADER_LEN + 1, host_len);

        if (use_kcp) {
            kcp_key = ntohs_by_data(buf, SOCKS5_CONN_HEADER_LEN + IPV4_LEN);
        }
        port = ntohs_by_data(buf, SOCKS5_CONN_HEADER_LEN + 1 + host_len + ext_len);
        multi_socks_epoll_server_buffer_remove(in, SOCKS5_CONN_HEADER_LEN + 1 + host_len + ext_len + PORT_LEN);
    }

    if (client->auth_cb)
        client->auth_cb(ev, SOCKS5_REPLY_SUCCEEDED, host, port, kcp_key, client->ctx);
}

static void socks5_client_connect_request(MultiSocksEvent *ev, void *ctx) {
    size_t buf_len = SOCKS5_CONN_HEADER_LEN + PORT_LEN;
    Client *client = ctx;
    struct sockaddr_storage addr;

    char a_type;
    if (str_is_ipv4(client->remote_host)) {
        buf_len += IPV4_LEN;
        a_type = SOCKS5_ATYPE_IPV4;
    } else if (strstr(client->remote_host, ":") != NULL) {
        buf_len += IPV6_LEN;
        a_type = SOCKS5_ATYPE_IPV6;
    } else {
        buf_len += 1 + strlen(client->remote_host);
        a_type = SOCKS5_ATYPE_DOMAINNAME;
    }
    LOGD("a type = %d: remote_host = %s, remote_port = %d", a_type, client->remote_host, client->remote_port);
    char buf[buf_len];
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;
    buf[3] = a_type;
    if (a_type == SOCKS5_ATYPE_IPV4) {
        n_write_uint32_t_to_data(buf, ((struct sockaddr_in *) &addr)->sin_addr.s_addr, SOCKS5_CONN_HEADER_LEN);
        n_write_u_short_to_data(buf, client->remote_port, SOCKS5_CONN_HEADER_LEN + IPV4_LEN);
    } else if (a_type == SOCKS5_ATYPE_IPV6) {
        memcpy(buf + SOCKS5_CONN_HEADER_LEN, &((struct sockaddr_in6 *) &addr)->sin6_addr, IPV6_LEN);
        n_write_u_short_to_data(buf, client->remote_port, SOCKS5_CONN_HEADER_LEN + IPV6_LEN);
    } else {
        buf[4] = (char) strlen(client->remote_host);
        memcpy(buf + SOCKS5_CONN_HEADER_LEN + 1, client->remote_host, (u_char) buf[4]);
        n_write_u_short_to_data(buf, client->remote_port, SOCKS5_CONN_HEADER_LEN + 1 + (u_char) buf[4]);
    }

    MultiSocksBuffer *out = multi_socks_ev_get_output(ev);
    hexDump(buf, buf_len, 0);
    multi_socks_epoll_server_buffer_write(out, buf, buf_len);

    multi_socks_ev_setcb(ev, socks5_client_connect_result_cb, NULL, socks5_client_event_cb, ctx);
}

static void socks5_client_auth_result_cb(MultiSocksEvent *ev, void *ctx) {
    LOGD("socks5 auth result callback");
    Client *client = ctx;
    MultiSocksBuffer *in = multi_socks_ev_get_input(ev);
    size_t len = multi_socks_epoll_server_buffer_get_length(in);

    if (len < 2) {
        LOGD("need read more data");
        return;
    }

    char data[2];
    if (multi_socks_epoll_server_buffer_copyout(in, data, sizeof(data)) != 2) {
        LOGE("copy data failed");
        if (client->auth_cb) client->auth_cb(NULL, -1, NULL, 0, 0, client->ctx);
        Client_free(client);
        return;
    }

    multi_socks_epoll_server_buffer_remove(in, sizeof(data));

    if (data[0] != SOCKS_USERNAME_PASSWORD_AUTH_VERSION_1) {
        LOGI("bad socks5 version: %d", data[0]);
        if (client->auth_cb) client->auth_cb(NULL, -1, NULL, 0, 0, client->ctx);
        Client_free(client);
        return;
    }

    if (data[1] != SOCKS_USERNAME_PASSWORD_AUTH_SUCCESS) {
        if (client->auth_cb) client->auth_cb(NULL, SOCKS5_REPLY_EXT_AUTH_FAILED, NULL, 0, 0, client->ctx);
        Client_free(client);
        return;
    }

    // send connect request
    socks5_client_connect_request(ev, ctx);
}

static void socks5_client_read_cb(MultiSocksEvent *ev, void *ctx) {
    LOGD("socks5 hello");
    Client *client = ctx;
    MultiSocksBuffer *in = multi_socks_ev_get_input(ev);
    size_t len = multi_socks_epoll_server_buffer_get_length(in);

    if (len < 2) {
        LOGD("need read more data");
        return;
    }

    char data[2];
    if (multi_socks_epoll_server_buffer_copyout(in, data, sizeof(data)) != 2) {
        LOGE("copy data failed");
        if (client->auth_cb) client->auth_cb(NULL, -1, NULL, 0, 0, client->ctx);
        Client_free(client);
        return;
    }
    multi_socks_epoll_server_buffer_remove(in, sizeof(data));

    if (data[0] != SOCKS5_VERSION) {
        LOGI("bad socks5 version: %d", data[0]);
        if (client->auth_cb) client->auth_cb(NULL, -1, NULL, 0, 0, client->ctx);
        Client_free(client);
        return;
    }

    if (data[1] == SOCKS5_METHOD_USERNAME_PASSWORD || (u_char) data[1] == SOCKS5_METHOD_KCP_USERNAME_PASSWORD) {
        if (auth_username == NULL || auth_password == NULL) {
            LOGE("bad auth info :auth_username = %s; auth_password = %s", auth_username, auth_password);
            if (client->auth_cb) client->auth_cb(NULL, -1, NULL, 0, 0, client->ctx);
            Client_free(client);
            return;
        }
        size_t msg_len = 2 + strlen(auth_username) + 1 + strlen(auth_password);
        char msg[msg_len];
        msg[0] = SOCKS_USERNAME_PASSWORD_AUTH_VERSION_1;
        msg[1] = (u_char) strlen(auth_username);
        memcpy(msg + 2, auth_username, strlen(auth_username));
        msg[2 + strlen(auth_username)] = (u_char) strlen(auth_password);
        memcpy(msg + 2 + strlen(auth_username) + 1, auth_password, strlen(auth_password));

        if ((u_char) data[1] == SOCKS5_METHOD_KCP_USERNAME_PASSWORD) {
            client->use_kcp = 1;
        }

        MultiSocksBuffer *out = multi_socks_ev_get_output(ev);
        multi_socks_epoll_server_buffer_write(out, msg, msg_len);
        multi_socks_ev_setcb(ev, socks5_client_auth_result_cb, NULL, socks5_client_event_cb, ctx);
    } else {
        socks5_client_connect_request(ev, ctx);
    }
}

static void socks5_client_event_cb(MultiSocksEvent *ev, int what, void *ctx) {
    LOGD("what = %x", what);
    Client *client = ctx;
    client->ev = ev;
    if (ev == NULL || MULTI_SOCKS_IS_ERROR(what)) {
        Client_free(client);
        return;
    }

    if (MULTI_SOCKS_IS_CONNECT(what)) {
        char methods[1 + 1 + CLIENT_MAX_SUPPORT_METHOD_COUNT];
        methods[0] = SOCKS5_VERSION;
        if (auth_username != NULL && auth_password != NULL) {
            if (use_kcp) {
                methods[1] = 4; // no auth request + u/p
                methods[2] = SOCKS5_METHOD_NO_AUTHENTICATION_REQUIRED;
                methods[3] = SOCKS5_METHOD_USERNAME_PASSWORD;
                methods[4] = SOCKS5_METHOD_KCP_NO_AUTHENTICATION_REQUIRED;
                methods[5] = SOCKS5_METHOD_KCP_USERNAME_PASSWORD;
            } else {
                methods[1] = 2; // no auth request + u/p
                methods[2] = SOCKS5_METHOD_NO_AUTHENTICATION_REQUIRED;
                methods[3] = SOCKS5_METHOD_USERNAME_PASSWORD;
            }
        } else {
            if (use_kcp) {
                methods[1] = 2; // no auth request
                methods[2] = SOCKS5_METHOD_NO_AUTHENTICATION_REQUIRED;
                methods[3] = SOCKS5_METHOD_KCP_NO_AUTHENTICATION_REQUIRED;
            } else {
                methods[1] = 1; // no auth request
                methods[2] = SOCKS5_METHOD_NO_AUTHENTICATION_REQUIRED;
            }
        }

        hexDump(methods, 2 + methods[1], 0);
        MultiSocksBuffer *out = multi_socks_ev_get_output(ev);
        multi_socks_epoll_server_buffer_write(out, methods, 2 + methods[1]);
    }
}

int socks5_client_auth(MultiSocksBase *base, char *host, u_short port, socks5_client_auth_cb cb, void *ctx) {
    LOGD("host = %s, port = %d", host, port);
    if (base == NULL) {
        LOGD("base is null");
        return -1;
    }

    MultiSocksEvent *ev = NULL;
    if (server_ssl) {
        ev = multi_socks_epoll_server_ssl_connect_hostname(base, -1, server_host, server_port, NULL);
    } else {
        ev = multi_socks_epoll_server_connect_hostname(base, -1, server_host, server_port, NULL);
    }
    if (ev == NULL) {
        LOGE("connect to (%s:%d) failed", server_host, server_port);
        return -1;
    }
    Client *client = Client_new(ev, host, port, cb, ctx);
    multi_socks_ev_setcb(ev, socks5_client_read_cb, NULL, socks5_client_event_cb, client);

    return 0;
}

int socks5_client_init(const char *host, u_short port, const char *username, const char *password) {
    LOGD("host = %s, port = %d, username = %s, password = %s", host, port, username, password);
    if (host == NULL || port == 0) {
        LOGE("init failed");
        return -1;
    }
    free(server_host);
    server_host = strdup(host);
    server_port = port;

    free(auth_username);
    free(auth_password);
    if (username != NULL && password != NULL) {
        auth_username = strdup(username);
        auth_password = strdup(password);
    } else {
        auth_username = NULL;
        auth_password = NULL;
    }

    return 0;
}

int socks5_client_init_ssl(const char *host, u_short port, const char *username, const char *password) {
    int result = socks5_client_init(host, port, username, password);

    if (result == 0) {
        server_ssl = true;
    }
    return result;
}

void socks5_client_set_use_kcp(int kcp) {
    use_kcp = kcp;
}