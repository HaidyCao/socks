#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>
#include <errno.h>
#include <stdbool.h>
#include <strings.h>

#include "socks5.h"
#include "../lib/clib.h"
#include "../log.h"
#include "../lib/c_hash_map.h"
#include "../lib/c_linked_list.h"
#include "../dependencies/kcp-1.7/ikcp.h"
#include "../lib/c_sparse_array.h"

#define KCP_HEADER_LEN 2

static int socks5_read_timeout = 0;
static int socks5_write_timeout = 0;

static CLinkedList *server_list;
static CHashMap *auth_info_map = NULL;

static int use_kcp = 0;

static int bind_type = -1;
static char *bind_addr = NULL;
static u_char bind_addr_len = 0;

static MultiSocksEvent *remote_connect_internal(char *host, int port, void *ctx);

static socks5_remote_connect_cb remote_connect_cb = remote_connect_internal;

void socks5_set_remote_connect_cb(socks5_remote_connect_cb cb) {
    remote_connect_cb = cb;
}

static void server_event_cb(MultiSocksEvent *event, int what, void *ctx);

static void disconnect_write_cb(MultiSocksEvent *event, void *ctx);

static void remote_event_cb(MultiSocksEvent *event, int what, void *ctx);

static void
kcp_write_cb(MultiSocksEvent *event, MultiSocksBuffer *buffer, struct sockaddr *addr, socklen_t addr_len, void *ctx);

struct socks5_config {
    MultiSocksBase *base;
    socks5_connect_to_remote cb;
};

Socks5Config *Socks5Config_new() {
    return (Socks5Config *) calloc(1, sizeof(Socks5Config));
}

void Socks5Config_free(Socks5Config *config) {
    free(config);
}

int socks5_config_set_cb(Socks5Config *config, socks5_connect_to_remote cb) {
    if (config == NULL)
        return -1;
    config->cb = cb;
    return 0;
}

struct socks5_context {
    int type;
    int status;

    unsigned char method;
    bool connecting;
    bool need_free;
    unsigned char remote_address_type;

    char *remote_host;
    int remote_port;

    char *username;
    char *password;

    Socks5Config *config;
    Socks5Context *partner;
    MultiSocksEvent *ev;
    MultiSocksEvent *kcp_ev;

    MultiSocksTimer *ev_timer;

    ikcpcb *kcp;
    IUINT32 next_time;
    struct sockaddr *client_addr;
    socklen_t client_addr_len;

    size_t reply_data_len;
    char reply_data[MAX_DOMAIN_LEN + 6];
    char *kcp_key;   // no need free
    char *bind_port; // no need free
};

Socks5Context *Socks5ContextRemote_new() {
    Socks5Context *socks5 = calloc(1, sizeof(Socks5Context));
    socks5->remote_host = NULL;
    return socks5;
}

Socks5Context *Socks5Context_new() {
    Socks5Context *socks5 = (Socks5Context *) calloc(1, sizeof(Socks5Context));
    socks5->remote_host = NULL;
    return socks5;
}

void Socks5Context_event_freed(Socks5Context *socks5) {
    socks5->ev = NULL;
    Socks5Context_free(socks5);
}

void Socks5Context_free(Socks5Context *socks5) {
    if (socks5 == NULL)
        return;

    if (socks5->connecting) {
        socks5->need_free = true;
        return;
    }

    socks5->config = NULL;
    if (socks5->ev)
        multi_socks_epoll_server_event_free(socks5->ev);
    socks5->ev = NULL;

    LOGD("username = %s, password = %s, remote_host = %s, replay_data = %p", socks5->username, socks5->password,
         socks5->remote_host, socks5->reply_data);

    free(socks5->username);
    free(socks5->password);
    free(socks5->remote_host);
    if (socks5->partner) {
        socks5->partner->partner = NULL;
        socks5->partner = NULL;
    }
    if (socks5->kcp_ev) {
        MultiSocksBuffer *kcp_out = multi_socks_ev_get_output(socks5->kcp_ev);
        if (multi_socks_epoll_server_buffer_get_length(kcp_out) == 0) {
            multi_socks_epoll_server_event_free(socks5->kcp_ev);
            socks5->kcp_ev = NULL;
        } else {
            multi_socks_ev_udp_setcb(socks5->kcp_ev, NULL, kcp_write_cb, NULL, NULL);
        }
    }

    free(socks5);
}

MultiSocksBase *socks5_context_get_base(Socks5Context *socks5) {
    if (socks5 == NULL || socks5->config == NULL)
        return NULL;
    return socks5->config->base;
}

void socks5_context_get_remote_address(Socks5Context *socks5, char **host, int *port) {
    if (socks5 == NULL)
        return;

    if (socks5->remote_host)
        *host = strdup(socks5->remote_host);
    *port = socks5->remote_port;
}

MultiSocksEvent *socks5_context_get_ev(Socks5Context *socks5) {
    if (socks5 == NULL)
        return NULL;
    return socks5->ev;
}

int socks5_context_set_ev(Socks5Context *socks5, MultiSocksEvent *ev) {
    if (socks5 == NULL)
        return -1;
    socks5->ev = ev;

    return 0;
}

int socks5_context_get_reply_data(Socks5Context *socks5, char **data, size_t *len) {
    if (socks5 == NULL)
        return -1;

    *data = socks5->reply_data;
    *len = socks5->reply_data_len;
    return 0;
}

static CSparseArray *kcp_array = NULL;

static u_short kcp_get_key() {
    u_short key = rand() % 65535;
    if (kcp_array == NULL)
        kcp_array = CSparseArray_new();
    while (CSparseArray_get(kcp_array, key) != NULL) {
        // rand again
    }
    return key;
}

static u_char negotication(char *methods, int size) {
    if (size <= 0) {
        return SOCKS5_METHOD_NO_ACCEPTABLE_METHODS;
    } else {
        int has_kcp_no_auth_request = 0;
        if (auth_info_map != NULL) {
            size_t i;
            if (use_kcp) {
                for (i = 0; i < size; i++) {
                    if ((u_char) methods[i] == SOCKS5_METHOD_KCP_USERNAME_PASSWORD) {
                        LOGD("use kcp username password");
                        return methods[i];
                    }

                    if (!has_kcp_no_auth_request)
                        has_kcp_no_auth_request = (u_char) methods[i] == SOCKS5_METHOD_KCP_NO_AUTHENTICATION_REQUIRED;
                }
            }

            for (i = 0; i < size; i++) {
                if ((u_char) methods[i] == SOCKS5_METHOD_USERNAME_PASSWORD) {
                    return SOCKS5_METHOD_USERNAME_PASSWORD;
                }
            }

            if (use_kcp && has_kcp_no_auth_request)
                return SOCKS5_METHOD_KCP_NO_AUTHENTICATION_REQUIRED;
            else
                return SOCKS5_METHOD_NO_ACCEPTABLE_METHODS;
        } else {
            int has_no_auth_request = 0;
            size_t i;
            for (i = 0; i < size; i++) {
                if (!has_kcp_no_auth_request)
                    has_kcp_no_auth_request = (u_char) methods[i] == SOCKS5_METHOD_KCP_NO_AUTHENTICATION_REQUIRED;

                if (!has_no_auth_request)
                    has_no_auth_request = (u_char) methods[i] == SOCKS5_METHOD_NO_AUTHENTICATION_REQUIRED;
            }
            if (use_kcp && has_kcp_no_auth_request)
                return SOCKS5_METHOD_KCP_NO_AUTHENTICATION_REQUIRED;
            else if (has_no_auth_request) {
                return SOCKS5_METHOD_NO_AUTHENTICATION_REQUIRED;
            } else
                return SOCKS5_METHOD_NO_ACCEPTABLE_METHODS;
        }
    }
}

static u_char auth(char *username, char *password) {
    char *p = c_hash_map_get(auth_info_map, username);
    if (p && strcmp(password, p) == 0) {
        return SOCKS_USERNAME_PASSWORD_AUTH_SUCCESS;
    }

    return 0xFF;
}

static void socks_remote_read(MultiSocksEvent *event, void *ctx) {
    Socks5Context *socks5 = (Socks5Context *) ctx;
    LOGD("type = %s", type_to_string(socks5->type));
    MultiSocksBuffer *in = multi_socks_ev_get_input(event);

    if (socks5->partner == NULL || socks5->partner->ev == NULL) {
        LOGD("partner is NULL");
        Socks5Context_free(socks5);
        return;
    }
    if (socks5->partner->kcp != NULL) {
        size_t len = multi_socks_epoll_server_buffer_get_length(in);
        if (len == 0) {
            return;
        }
        char buf[len];
        LOGD("ikcp_send buffer len = %zu", len);
        socks5->partner->next_time = 0;
        multi_socks_epoll_server_buffer_copyout(in, buf, len);
        multi_socks_epoll_server_buffer_remove(in, len);

        size_t mtu = socks5->partner->kcp->mtu;
        char *ptr = buf;
        size_t left = len;
        while (1) {
            if (left <= mtu) {
                ikcp_send(socks5->partner->kcp, ptr, left);
                break;
            } else {
                ikcp_send(socks5->partner->kcp, ptr, mtu);
                left -= mtu;
                ptr += mtu;
            }
        }
        return;
    }
    MultiSocksBuffer *out = multi_socks_ev_get_output(socks5->partner->ev);
    multi_socks_epoll_server_buffer_add_buffer(out, in);
}

static void socks_read_cb(MultiSocksEvent *event, void *ctx) {
    Socks5Context *socks5 = (Socks5Context *) ctx;
    LOGD("type = %s", type_to_string(socks5->type));
    MultiSocksBuffer *in = multi_socks_ev_get_input(event);

    if (socks5->partner == NULL || socks5->partner->ev == NULL) {
        LOGD("partner is NULL");
        Socks5Context_free(socks5);
        return;
    }

    MultiSocksBuffer *out = multi_socks_ev_get_output(socks5->partner->ev);
    multi_socks_epoll_server_buffer_add_buffer(out, in);
}

static void
kcp_read_cb(MultiSocksEvent *event, MultiSocksBuffer *buffer, struct sockaddr *addr, socklen_t addr_len, void *ctx) {
    LOGD("kcp read");
    Socks5Context *server = ctx;
    size_t len = multi_socks_epoll_server_buffer_get_length(buffer);
    char buf[len];
    multi_socks_epoll_server_buffer_copyout(buffer, buf, len);
    multi_socks_epoll_server_buffer_remove(buffer, len);
    server->next_time = 0;

    if (server->client_addr == NULL) {
        server->client_addr = malloc(addr_len);
        server->client_addr_len = addr_len;
        memcpy(server->client_addr, addr, addr_len);
    }

    ikcp_input(server->kcp, buf, len);
    int r_len;
    while ((r_len = ikcp_recv(server->kcp, buf, len)) > 0) {
        LOGD("ikcp_recv len = %d", r_len);
        Socks5Context *remote = server->partner;
        MultiSocksBuffer *out = multi_socks_ev_get_output(remote->ev);
        multi_socks_epoll_server_buffer_write(out, buf, r_len);
    }
}

static void
kcp_write_cb(MultiSocksEvent *event, MultiSocksBuffer *buffer, struct sockaddr *addr, socklen_t addr_len, void *ctx) {
    if (ctx != NULL)
        return;
    if (multi_socks_epoll_server_buffer_get_length(buffer) == 0) {
        LOGD("kcp close");
        Socks5Context *server = ctx;
        Socks5Context_free(server);
    }
}

static void kcp_event_cb(MultiSocksEvent *event, int what, void *ctx) {
    LOGE("what = %x", what);
    Socks5Context *server = ctx;
    Socks5Context *remote = server->partner;

    Socks5Context_free(server);
    Socks5Context_free(remote);
}

static int udp_output(const char *buf, int len, ikcpcb *kcp, void *user) {
    LOGD("udp output");
    Socks5Context *server = user;
    if (server->kcp_ev == NULL)
        return -1;
    LOGD("send to: %s", sockaddr_to_string(server->client_addr, NULL, 0));
//    hexDump((char *) buf, len, 0);

    MultiSocksBuffer *out = multi_socks_ev_udp_get_output(server->kcp_ev, server->client_addr, server->client_addr_len);
    multi_socks_epoll_server_buffer_sendto(out, (char *) buf, len, server->client_addr, server->client_addr_len);
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


static void kcp_timer_cb(MultiSocksTimer *timer, void *ctx) {
    Socks5Context *server = ctx;
//    LOGD("kcp update timer: next time = %lu", (long) server->next_time);

    IUINT32 current = iclock();

    if (server->next_time <= current)
        ikcp_update(server->kcp, current);

    IUINT32 next = ikcp_check(server->kcp, current);
    server->next_time = next;
//    LOGD("now = %lu, next = %lu", (long) current, (long) next);
}

static void send_client_auth_response(Socks5Context *remote, Socks5Context *server, void *ctx) {
    LOGD("remote connect success");

    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    u_short port = 0;
    if (bind_type == -1) {
        switch (server->remote_address_type) {
            case SOCKS5_ATYPE_IPV4: {
                char address[MAX_IPV4_ADDRESS_LEN + 1];
                bzero(address, sizeof(address));
                sprintf(address, "%s:%d", server->remote_host, server->remote_port);
                parse_address(address, (struct sockaddr *) &addr, &addr_len);
                break;
            }
            case SOCKS5_ATYPE_IPV6: {
                char address[MAX_IPV6_ADDRESS_LEN + 1];
                bzero(address, sizeof(address));
                sprintf(address, "%s:%d", server->remote_host, server->remote_port);
                parse_address(address, (struct sockaddr *) &addr, &addr_len);
                break;
            }
            case SOCKS5_ATYPE_DOMAINNAME:
                parse_address("127.0.0.1:1080", (struct sockaddr *) &addr, &addr_len);
                break;
            default:
                LOGD("server remote address type not support: %d", server->remote_address_type);
                Socks5Context_free(remote);
                return;
        }
    } else {
        if (bind_type == SOCKS5_ATYPE_DOMAINNAME) {
            parse_address("0.0.0.0:0", (struct sockaddr *) &addr, &addr_len);
            server->reply_data_len = SOCKS5_CONN_HEADER_LEN + 1 + addr_len + PORT_LEN;
        } else if (bind_type == SOCKS5_ATYPE_IPV4) {
            struct sockaddr_in *in = (struct sockaddr_in *) &addr;
            in->sin_addr.s_addr = INADDR_ANY;
            in->sin_family = AF_INET;
            in->sin_port = 0;

            server->reply_data_len = SOCKS5_CONN_HEADER_LEN + IPV4_LEN + PORT_LEN;
        } else if (bind_type == SOCKS5_ATYPE_IPV6) {
            struct sockaddr_in6 *in = (struct sockaddr_in6 *) &addr;
            void *in6_addr = &in->sin6_addr;
            in->sin6_addr = in6addr_any;
            memcpy(in6_addr, bind_addr, bind_addr_len);
            in->sin6_family = AF_INET6;
            in->sin6_port = 0;

            server->reply_data_len = SOCKS5_CONN_HEADER_LEN + IPV6_LEN + PORT_LEN;
        }

        int fd = multi_socks_epoll_server_event_get_fd(remote->ev);
        struct sockaddr_storage local_addr;
        socklen_t local_addr_len;
        if (getsockname(fd, ((struct sockaddr *) &local_addr), &local_addr_len) == -1) {
            LOGE("getsockname failed: errno = %d, err = %s", errno, strerror(errno));
            return;
        }
        if (local_addr.ss_family == AF_INET) {
            port = ntohs(((struct sockaddr_in *) &local_addr)->sin_port);
        } else {
            port = ntohs(((struct sockaddr_in6 *) &local_addr)->sin6_port);
        }
    }

    if (use_kcp && ((u_char) server->method == SOCKS5_METHOD_KCP_NO_AUTHENTICATION_REQUIRED ||
                    (u_char) server->method == SOCKS5_METHOD_KCP_USERNAME_PASSWORD)) {

        MultiSocksEvent *kcp_ev = multi_socks_epoll_server_udp(socks5_context_get_base(server), -1,
                                                               (struct sockaddr *) &addr, addr_len, NULL);
        if (kcp_ev == NULL) {
            LOGD("bind udp failed");
            Socks5Context_free(server);
            Socks5Context_free(remote);
            return;
        }
        server->kcp_ev = kcp_ev;

        int fd = multi_socks_epoll_server_event_get_fd(kcp_ev);
        if (fd == -1) {
            LOGD("get fd of udp event failed");
            Socks5Context_free(server);
            Socks5Context_free(remote);
            return;
        }

        socklen_t kcp_addr_len = sizeof(addr);
        if (getsockname(fd, (struct sockaddr *) &addr, &kcp_addr_len) == -1) {
            LOGD("getsockname of udp event failed");
            Socks5Context_free(server);
            Socks5Context_free(remote);
            return;
        }

        if (addr.ss_family == AF_INET)
            port = ntohs(((struct sockaddr_in *) &addr)->sin_port);
        else
            port = ntohs(((struct sockaddr_in6 *) &addr)->sin6_port);

        u_short key = kcp_get_key();
        LOGD("key = %d", key);
        server->kcp = ikcp_create(key, server);
        ikcp_setoutput(server->kcp, udp_output);
        multi_socks_epoll_server_event_set_timer(kcp_ev, 10, kcp_timer_cb, server);

        n_write_u_short_to_data(server->kcp_key, key, 0);

        multi_socks_ev_udp_setcb(server->kcp_ev, kcp_read_cb, kcp_write_cb, kcp_event_cb, server);

        // cancel ev timer
        multi_socks_epoll_server_stop_timer(server->ev_timer);
        server->ev_timer = NULL;
        server->reply_data_len += KCP_HEADER_LEN;
    }
    if (server->bind_port) {
        n_write_u_short_to_data(server->bind_port, port, 0);
    }

    MultiSocksBuffer *out = multi_socks_ev_get_output(server->ev);
    multi_socks_epoll_server_buffer_write(out, server->reply_data, server->reply_data_len);

    multi_socks_ev_setcb(remote->ev, socks_remote_read, NULL, remote_event_cb, ctx);
    multi_socks_ev_setcb(server->ev, socks_read_cb, NULL, server_event_cb, server);
}

static void remote_event_cb(MultiSocksEvent *event, int what, void *ctx) {
    LOGD("what = %x", what);
    Socks5Context *remote = (Socks5Context *) ctx;
    Socks5Context *server = remote->partner;
    remote->ev = event;

    if (server == NULL || event == NULL || MULTI_SOCKS_IS_ERROR(what)) {
        LOGD("server is NULL");
        Socks5Context_free(remote);
        return;
    }

    if (server->ev != NULL && MULTI_SOCKS_IS_CONNECT(what)) {
        send_client_auth_response(remote, server, ctx);
    } else {
        LOGD("server ev = %p, remote ev = %p", server->ev, remote->ev);
        Socks5Context_free(remote);
        if (server->kcp) {
            server->next_time = 0;
            if (ikcp_waitsnd(server->kcp) > 0) {
                LOGD("server wait send");
                server->status = SOCKS_STATUS_WAIT_DISCONNECT;
                return;
            }
        }
        Socks5Context_free(server);
    }
}

static void disconnect_write_cb(MultiSocksEvent *event, void *ctx) {
    Socks5Context *socks5 = (Socks5Context *) ctx;
    MultiSocksBuffer *out = multi_socks_ev_get_output(event);
    int len = multi_socks_epoll_server_buffer_get_length(out);
    LOGD("out len = %d", len);

    if (len == 0) {
        multi_socks_epoll_server_event_free(event);
        Socks5Context_free(socks5);
    }
}

static uint16_t port_to_uint16(const unsigned char *data) {
    uint16_t a = (uint16_t) ((uint16_t) ((uint16_t) (data[0] << (uint8_t) 8) & (uint16_t) 0xFF00) |
                             (uint16_t) (data[1] & (uint8_t) 0xFF));
    return a;
}

static MultiSocksEvent *remote_connect_internal(char *host, int port, void *ctx) {
    Socks5Context *remote = (Socks5Context *) ctx;
    return multi_socks_epoll_server_connect_hostname(remote->config->base, -1, host, port, remote);
}

static void server_method_conn_read_cb(MultiSocksEvent *event, void *ctx) {
    Socks5Context *server = (Socks5Context *) ctx;
    MultiSocksBuffer *in = multi_socks_ev_get_input(event);
    MultiSocksBuffer *out = multi_socks_ev_get_output(event);
    int len = multi_socks_epoll_server_buffer_get_length(in);

    if (len < SOCKS5_CONN_HEADER_LEN) {
        LOGD("len = %d, need read more data", len);
        return;
    }

    char data[len];
    multi_socks_epoll_server_buffer_copyout(in, data, len);
    LOGD("request data header: %x, %x, %x, %x", data[0], data[1], data[2], data[3]);

    if (data[0] != SOCKS5_VERSION) {
        LOGI("request version (%x) not supported", (u_char) 0xFF & (u_char) data[0]);
        Socks5Context_free(server);
        return;
    }

    char resp = SOCKS5_REPLY_SUCCEEDED;
    if (data[1] != SOCKS5_CMD_CONNECT) {
        LOGI("command(%d) not support", data[1]);
        resp = SOCKS5_REPLY_COMMAND_NOT_SUPPORTED;
    }

    if (data[2] != 0x00) {
        LOGI("bad reserved(%d)", data[2]);
        Socks5Context_free(server);
        return;
    }

    char atype = data[3];
    if (atype != SOCKS5_ATYPE_IPV4 && atype != SOCKS5_ATYPE_DOMAINNAME && atype != SOCKS5_ATYPE_IPV6) {
        LOGI("unsupport address type");
        Socks5Context_free(server);
        return;
    }

    char req_addr[MAX_DOMAIN_LEN];
    int req_addr_len;
    unsigned char port[2];
    server->remote_address_type = atype;
    if (atype == SOCKS5_ATYPE_IPV4) {
        if (len - SOCKS5_CONN_HEADER_LEN < (IPV4_LEN + PORT_LEN)) {
            LOGI("wait more data for Requests");
            return;
        }
        char *ip = data + SOCKS5_CONN_HEADER_LEN;

        struct sockaddr_in addr_in;
        addr_in.sin_addr.s_addr = ipv4_to_int(ip);
        char *ip_str = inet_ntoa(addr_in.sin_addr);
        if (ip_str == NULL) {
            LOGI("parse ipv4 failed");
            Socks5Context_free(server);
            return;
        }

        server->remote_host = strdup(ip_str);

        unsigned char port_data[PORT_LEN] = {data[SOCKS5_CONN_HEADER_LEN + IPV4_LEN],
                                             data[SOCKS5_CONN_HEADER_LEN + IPV4_LEN + 1]};
        server->remote_port = port_to_uint16(port_data);
        req_addr_len = IPV4_LEN;
        memcpy(req_addr, ip, req_addr_len);
        memcpy(port, port_data, PORT_LEN);

        LOGI("request remote address: host = %s, port = %d", server->remote_host, server->remote_port);
        multi_socks_epoll_server_buffer_remove(in, SOCKS5_CONN_HEADER_LEN + IPV4_LEN + PORT_LEN);
    } else if (atype == SOCKS5_ATYPE_IPV6) {
        if (len - SOCKS5_CONN_HEADER_LEN < (IPV6_LEN + PORT_LEN)) {
            LOGI("wait more data for Requests");
            return;
        }
        char ip[IPV6_LEN];
        memcpy(ip, data + SOCKS5_CONN_HEADER_LEN, IPV6_LEN);

        struct sockaddr_in6 addr_in6;
        // addr_in->sin6_addr
        server->remote_host = ipv6_to_string(ip);
        if (inet_pton(AF_INET6, server->remote_host, &addr_in6.sin6_addr) != 1) {
            LOGI("parse ipv6 failed");
            Socks5Context_free(server);
            return;
        }

        unsigned char port_data[PORT_LEN] = {data[SOCKS5_CONN_HEADER_LEN + IPV6_LEN],
                                             data[SOCKS5_CONN_HEADER_LEN + IPV6_LEN + 1]};
        server->remote_port = port_to_uint16(port_data);

        req_addr_len = IPV6_LEN;
        memcpy(req_addr, ip, req_addr_len);
        memcpy(port, port_data, PORT_LEN);

        multi_socks_epoll_server_buffer_remove(in, SOCKS5_CONN_HEADER_LEN + IPV6_LEN + PORT_LEN);
    } else /*if (atype == SOCKS5_ATYPE_DOMAINNAME)*/ {
        if (len <= SOCKS5_CONN_HEADER_LEN) {
            LOGI("wait more data for domain");
            return;
        }

        int domain_len = (unsigned char) data[SOCKS5_CONN_HEADER_LEN];
        if (domain_len <= 0 || domain_len > MAX_DOMAIN_LEN) {
            LOGE("bad domain len: %d", domain_len);
            Socks5Context_free(server);
            return;
        }

        if (len < SOCKS5_CONN_HEADER_LEN + 1 + domain_len + PORT_LEN) {
            LOGI("wait more data for domain");
            return;
        }

        server->remote_host = strndup(data + SOCKS5_CONN_HEADER_LEN + 1, domain_len);
        memcpy(port, data + SOCKS5_CONN_HEADER_LEN + 1 + domain_len, PORT_LEN);
        LOGD("port[0] = %x, [1] = %x", port[0], ((u_short) port[1]) & (u_char) 0xFF);
        server->remote_port = port_to_uint16(port);

        req_addr_len = 1 + domain_len;
        req_addr[0] = (char) domain_len;
        memcpy(req_addr + 1, server->remote_host, domain_len);

        LOGI("request remote address: host = %s, port = %d", server->remote_host, server->remote_port);
        multi_socks_epoll_server_buffer_remove(in, SOCKS5_CONN_HEADER_LEN + 1 + domain_len + PORT_LEN);
    }

    char resp_atype = atype;

    server->reply_data_len = SOCKS5_CONN_HEADER_LEN + req_addr_len + 2;
    LOGD("socks reply data len = %zu, addr = %s:%d", server->reply_data_len, server->remote_host, server->remote_port);
    char *resp_data = server->reply_data;
    resp_data[0] = SOCKS5_VERSION;
    resp_data[1] = resp;
    resp_data[2] = 0x00;
    if (bind_type == -1) {
        LOGD("use req addr info");
        resp_data[3] = resp_atype;
        char *addr_ptr = resp_data + 4;

        memcpy(addr_ptr, req_addr, req_addr_len);

        char *port_ptr = addr_ptr + req_addr_len;
        memcpy(port_ptr, port, 2);
    } else {
        LOGD("use bind info: type = %d", atype);
        resp_data[3] = (char) bind_type;

        if (use_kcp && ((u_char) server->method == SOCKS5_METHOD_KCP_NO_AUTHENTICATION_REQUIRED ||
                        (u_char) server->method == SOCKS5_METHOD_KCP_USERNAME_PASSWORD)) {
            if (bind_type == SOCKS5_ATYPE_DOMAINNAME) {
                resp_data[4] = bind_addr_len;
                memcpy(resp_data + 5, bind_addr, bind_addr_len);
                server->kcp_key = resp_data + 5 + bind_addr_len;
                server->bind_port = resp_data + 5 + bind_addr_len + 2;
            } else {
                memcpy(resp_data + 4, bind_addr, bind_addr_len);
                server->kcp_key = resp_data + 4 + bind_addr_len;
                server->bind_port = resp_data + 4 + bind_addr_len + 2;
            }
        } else {
            if (bind_type == SOCKS5_ATYPE_DOMAINNAME) {
                resp_data[4] = bind_addr_len;
                memcpy(resp_data + 5, bind_addr, bind_addr_len);
                server->bind_port = resp_data + 5 + bind_addr_len;
            } else {
                memcpy(resp_data + 4, bind_addr, bind_addr_len);
                server->bind_port = resp_data + 4 + bind_addr_len;
            }
        }
    }

    if (resp == SOCKS5_REPLY_SUCCEEDED) {
        if (server->config->cb) {
            LOGD("connect by custom callback");
            server->config->cb(server);
            return;
        }

        // connect to remote
        Socks5Context *remote = Socks5ContextRemote_new();
        remote->type = SOCKS_TYPE_REMOTE;
        remote->config = server->config;
        remote->ev = remote_connect_cb(server->remote_host, server->remote_port, remote);

        if (remote->ev == NULL) {
            if (remote_connect_cb == remote_connect_internal) {
                resp_data[1] = SOCKS5_REPLY_NETWORK_UNREACHABLE;
                multi_socks_epoll_server_buffer_write(out, resp_data, server->reply_data_len);
                server->status = SOCKS_STATUS_WAIT_DISCONNECT;
                multi_socks_ev_setcb(event, NULL, disconnect_write_cb, server_event_cb, ctx);
                return;
            } else {
                // custom connect to remote
                LOGD("custom remote is connecting");
                remote->connecting = true;
            }
        }
        if (remote->ev)
            remote->ev_timer = multi_socks_epoll_server_event_set_timeout(remote->ev, socks5_read_timeout * 1000,
                                                                          socks5_write_timeout * 1000);
        remote->partner = server;
        server->partner = remote;

        multi_socks_ev_setcb(event, NULL, NULL, server_event_cb, server);

        if (remote->ev)
            multi_socks_ev_setcb(remote->ev, NULL, NULL, remote_event_cb, remote);
    } else {
        multi_socks_epoll_server_buffer_write(out, resp_data, server->reply_data_len);
        server->status = SOCKS_STATUS_WAIT_DISCONNECT;
        multi_socks_ev_setcb(event, NULL, disconnect_write_cb, server_event_cb, ctx);
    }
}

void socks5_set_remote_event(MultiSocksEvent *event, void *ctx) {
    Socks5Context *remote = ctx;
    Socks5Context *server = remote->partner;
    remote->connecting = false;
    if (remote->need_free || event == NULL || server == NULL) {
        Socks5Context_free(remote);
        return;
    }

    remote->ev = event;
    remote->ev_timer = multi_socks_epoll_server_event_set_timeout(remote->ev, socks5_read_timeout * 1000,
                                                                  socks5_write_timeout * 1000);
    send_client_auth_response(remote, server, ctx);
}

static void server_method_resp_auth_read_cb(MultiSocksEvent *event, void *ctx) {
    Socks5Context *server = (Socks5Context *) ctx;
    MultiSocksBuffer *in = multi_socks_ev_get_input(event);
    MultiSocksBuffer *out = multi_socks_ev_get_output(event);
    int len = multi_socks_epoll_server_buffer_get_length(in);

    if (len < 2) {
        LOGD("len = %d, need read more data", len);
        return;
    }
    char data[len];

    if (multi_socks_epoll_server_buffer_copyout(in, data, len) == -1) {
        LOGD("read data failed");
        Socks5Context_free(server);
        return;
    }

    if (data[0] != SOCKS5_VERSION) {
        LOGE("username protocol version(%d) not support", data[0]);
        Socks5Context_free(server);
        return;
    }

    size_t username_len = (u_char) 0xff & (u_char) data[1];

    if (len - 2 < username_len) {
        LOGI("wait more data for username");
        return;
    }

    char u[username_len];
    memcpy(u, data + 2, username_len);

    int pwd_len = data[2 + username_len];
    if (len - 2 - username_len - 1 < pwd_len) {
        LOGD("wait more data for password");
        return;
    }

    char p[pwd_len];
    memcpy(p, data + 2 + username_len + 1, pwd_len);
    multi_socks_epoll_server_buffer_remove(in, 2 + username_len + 1 + pwd_len);

    server->username = strndup(u, username_len);
    server->password = strndup(p, pwd_len);
    char resp[2] = {SOCKS5_VERSION, auth(server->username, server->password)};
    multi_socks_epoll_server_buffer_write(out, resp, 2);
    multi_socks_ev_setcb(event, server_method_conn_read_cb, NULL, server_event_cb, ctx);
}

static void server_method_read_cb(MultiSocksEvent *event, void *ctx) {
    Socks5Context *server = (Socks5Context *) ctx;
    MultiSocksBuffer *in = multi_socks_ev_get_input(event);
    MultiSocksBuffer *out = multi_socks_ev_get_output(event);
    int len = multi_socks_epoll_server_buffer_get_length(in);
    if (len < 2) {
        LOGE("need read more data");
        return;
    }

    char version_methods[2];
    multi_socks_epoll_server_buffer_copyout(in, version_methods, sizeof(version_methods));
    if (version_methods[0] != SOCKS5_VERSION) {
        Socks5Context_free(server);
        return;
    }

    int methods_count = version_methods[1];
    if (len - methods_count < 2) {
        LOGI("socks_read_cb not received all methods");
        return;
    }

    multi_socks_epoll_server_buffer_remove(in, 2);
    char methods[methods_count];
    multi_socks_epoll_server_buffer_copyout(in, methods, methods_count);
    multi_socks_epoll_server_buffer_remove(in, methods_count);

    int i;
    for (i = 0; i < methods_count; i++) {
        LOGD("client supported method[%d:%d] = %x", i, methods[i], methods_count);
    }

    u_char method = negotication(methods, methods_count);
    LOGD("negotication = %x", (method & (u_char) 0xFF));
    char methods_resp[2];
    methods_resp[0] = SOCKS5_VERSION;
    methods_resp[1] = method;

    if (multi_socks_epoll_server_buffer_write(out, methods_resp, sizeof(methods_resp)) == -1) {
        LOGE("write data failed");
        Socks5Context_free(server);
        return;
    }

    server->method = method;
    if (server->method == SOCKS5_METHOD_NO_AUTHENTICATION_REQUIRED ||
        server->method == SOCKS5_METHOD_KCP_NO_AUTHENTICATION_REQUIRED)
        multi_socks_ev_setcb(event, server_method_conn_read_cb, NULL, server_event_cb, ctx);
    else
        multi_socks_ev_setcb(event, server_method_resp_auth_read_cb, NULL, server_event_cb, ctx);
}

static void server_event_cb(MultiSocksEvent *event, int what, void *ctx) {
    Socks5Context *server = (Socks5Context *) ctx;
    server->ev = event;

    Socks5Context_free(server);
    Socks5Context_free(server->partner);
}

static void
socks5_connect_cb(MultiSocksEVListener *l, int fd, struct sockaddr *addr, int addr_len, MultiSocksEvent *event,
                  void *ctx) {
    LOGD("fd = %d, addr = %s", fd, sockaddr_to_string(addr, NULL, 0));
    Socks5Config *config = (Socks5Config *) ctx;

    Socks5Context *socks5 = Socks5Context_new();
    socks5->config = config;
    socks5->ev = event;
    socks5->type = SOCKS_TYPE_CLIENT;

    multi_socks_epoll_server_event_set_timeout(event, socks5_read_timeout * 1000, socks5_write_timeout * 1000);
    multi_socks_ev_setcb(event, server_method_read_cb, NULL, server_event_cb, socks5);
}

int socks5_add_auth_info(const char *username, const char *password) {
    if (username == NULL || password == NULL) {
        LOGE("add auth info failed: username = %s, password = %s", username, password);
        return -1;
    }
    if (auth_info_map == NULL) {
        auth_info_map = c_hash_map_new();
        c_hash_map_set_free_cb(auth_info_map, free);
    }

    c_hash_map_put(auth_info_map, (char *) username, strdup(password));
    return 0;
}

void socks5_set_timeout(int read_timeout, int write_timeout) {
    socks5_read_timeout = read_timeout;
    socks5_write_timeout = write_timeout;
}

void socks5_set_use_kcp(int kcp) {
    use_kcp = kcp;
}

int socks5_set_bind_addr(int type, char *addr, u_char addr_len) {
    if ((type != SOCKS5_ATYPE_IPV4 && type != SOCKS5_ATYPE_IPV6 && type != SOCKS5_ATYPE_DOMAINNAME) || addr == NULL ||
        addr_len == 0) {
        LOGE("set bind addr failed: type = %d, addr = %p, addr_len = %zu", type, addr, (size_t) addr_len);
        return -1;
    }
    bind_type = type;
    bind_addr = malloc(addr_len);
    memcpy(bind_addr, addr, addr_len);
    bind_addr_len = addr_len;
    return 0;
}

static void handler(int sig) {
    LOGD("sig = %d", sig);
    void *h = NULL;

    while ((h = c_linked_list_get_header(server_list)) != NULL) {
        Socks5Config *config = (Socks5Config *) h;
        multi_socks_base_free(config->base);
        c_linked_list_remove_header(server_list);
    }

    exit(0);
}

int socks5_event_listen_init_internal(MultiSocksBase *base, struct sockaddr *addr, socklen_t addr_len, void *ssl_ctx,
                                      Socks5Config *config) {
    if (config == NULL)
        config = Socks5Config_new();
    if (base == NULL)
        base = multi_socks_ev_base_new();

    config->base = base;

    if (use_kcp) {
        srand((uint) (rand() % 4096));
    }

#ifdef SOCKS_SSL
    if (ssl_ctx) {
        if (multi_socks_ev_ssl_listen(base, socks5_connect_cb, -1, addr, addr_len, ssl_ctx, config) == NULL) {
            LOGE("start tcp socks5 server failed");
            return -1;
        }
    } else
#endif
    if (multi_socks_ev_listen(base, socks5_connect_cb, -1, addr, addr_len, config) == NULL) {
        LOGE("start tcp socks5 server failed");
        return -1;
    }
    multi_socks_epoll_server_set_dns_server(config->base, "114.114.114.114");
    c_linked_list_add(server_list, config);
    return 0;
}

int socks5_event_listen_init(MultiSocksBase *base, struct sockaddr *addr, socklen_t addr_len, Socks5Config *config) {
    return socks5_event_listen_init_internal(base, addr, addr_len, NULL, config);
}

#ifdef SOCKS_SSL

int socks5_event_ssl_listen_init(MultiSocksBase *base, struct sockaddr *addr, socklen_t addr_len, SSL_CTX *ssl_ctx,
                                 Socks5Config *config) {
    if (ssl_ctx == NULL) {
        return -1;
    }
    return socks5_event_listen_init_internal(base, addr, addr_len, ssl_ctx, config);
}

#endif

int socks5_event_init(MultiSocksBase *base, const char *ip, int port, Socks5Config *config) {
    if (ip == NULL || strlen(ip) == 0)
        return -1;

    int ipv6 = 0;
    size_t i;
    for (i = 0; i < strlen(ip); i++) {
        if (ip[i] == ':') {
            ipv6 = 1;
            break;
        }
    }

    char addr_str[strlen(ip) + 7];
    bzero(addr_str, sizeof(addr_str));
    if (ipv6) {
        sprintf(addr_str, "[%s]:%d", ip, port);
    } else {
        sprintf(addr_str, "%s:%d", ip, port);
    }

    if (server_list == NULL)
        server_list = c_linked_list_new();

    struct sockaddr_storage addr;

    socklen_t addr_len = sizeof(struct sockaddr);
    if (parse_address(addr_str, (struct sockaddr *) &addr, &addr_len) == -1) {
        LOGE("parse sockaddr failed");
        return -1;
    }

    return socks5_event_listen_init(base, (struct sockaddr *) &addr, addr_len, config);
}

int socks5_start(const char *ip, int port, Socks5Config *config) {
    LOGI("start server ip = %s; port = %d", ip, port);
    socks5_event_init(NULL, ip, port, config);
    signal(SIGINT, handler);

    return multi_socks_ev_loop(config->base);
}