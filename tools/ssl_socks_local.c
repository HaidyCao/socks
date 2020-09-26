//
// Created by Haidy on 2020/9/11.
//
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <regex.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>

#include "../event/multi_socks_epoll_server.h"
#include "../lib/clib.h"
#include "../log.h"
#include "../socks5/socks5.h"
#include "../socks5/socks5_client.h"
#include "../lib/c_hash_set.h"
#include "../lib/c_array_list.h"

#define MAX_BUFFER_SIZE 1024 * 100

static char *workd_dir = NULL;
static MultiSocksBase *g_base = NULL;
static char *remote_host = NULL;
static int remote_port = 0;

static bool ssl_clear = false;
static bool auth_clear = false;
static char *socks5_username = NULL;
static char *socks5_password = NULL;

static CHashSet *g_sub_domain_set = NULL;
static CHashSet *g_full_domain_set = NULL;
static CArrayList *g_reg_domain_array = NULL;
static regex_t g_domain_reg;

typedef struct {
    MultiSocksEvent *ev;
    MultiSocksEvent *partner;
} Context;

static Context *Context_new(MultiSocksEvent *ev, MultiSocksEvent *partner) {
    Context *context = malloc(sizeof(Context));
    context->ev = ev;
    context->partner = partner;

    return context;
}

static void Context_free(Context *context) {
    if (context->ev) {
        multi_socks_epoll_server_event_free(context->ev);
        context->ev = NULL;
    }

    if (context->partner) {
        multi_socks_epoll_server_event_free(context->partner);
        context->partner = NULL;
    }

    free(context);
}

static void ssl_write_cb(MultiSocksEvent *ev, void *ctx);

static void ssl_event_cb(MultiSocksEvent *ev, int what, void *ctx);

static void ssl_read_cb(MultiSocksEvent *ev, void *ctx) {
    Context *context = ctx;
    MultiSocksEvent *partner = context->partner;

    if (partner == NULL) {
        Context_free(context);
        return;
    }

    char *data;
    size_t len;
    MultiSocksBuffer *in = multi_socks_ev_get_input(ev);
    ssize_t result = multi_socks_epoll_server_buffer_move_out(in, &data, &len);
    if (result == -1) {
        LOGE("data move out failed");
        Context_free(context);
        return;
    }

    MultiSocksBuffer *out = multi_socks_ev_get_output(partner);
    multi_socks_epoll_server_buffer_write(out, data, len);
    free(data);

    size_t partner_out_len = multi_socks_epoll_server_buffer_get_length(out);
    if (partner_out_len >= MAX_BUFFER_SIZE) {
        multi_socks_epoll_server_event_disable_read(ev);
        multi_socks_ev_setcb(ev, NULL, ssl_write_cb, ssl_event_cb, context);
    }
}

static void ssl_write_cb(MultiSocksEvent *ev, void *ctx) {
    Context *context = ctx;
    MultiSocksEvent *partner = context->partner;

    if (partner == NULL) {
        Context_free(context);
        return;
    }

    MultiSocksBuffer *out = multi_socks_ev_get_output(partner);
    size_t partner_out_len = multi_socks_epoll_server_buffer_get_length(out);
    if (partner_out_len == 0) {
        multi_socks_epoll_server_event_enable_read(ev);
        multi_socks_ev_setcb(ev, ssl_read_cb, NULL, ssl_event_cb, context);
    }
}

static void ssl_event_cb(MultiSocksEvent *ev, int what, void *ctx) {
    Context *context = ctx;
    context->ev = ev;
    if (ev == NULL || MULTI_SOCKS_IS_EOF(what)) {
        Context_free(context);
        return;
    }

    multi_socks_ev_setcb(context->ev, ssl_read_cb, NULL, ssl_event_cb, context);
    multi_socks_ev_setcb(context->partner, ssl_read_cb, NULL, ssl_event_cb,
                         multi_socks_epoll_server_event_get_ctx(context->partner));
}

static void
ssl_clear_ev_conn(MultiSocksEVListener *l, int fd, struct sockaddr *addr, int addr_len, MultiSocksEvent *event,
                  void *ctx) {
    LOGD("fd = %d, socket = %s", fd, sockaddr_to_string(addr, NULL, 0));
    void *base = ctx;

    MultiSocksEvent *ev = NULL;

    if (ssl_clear) {
        ev = multi_socks_epoll_server_ssl_connect_hostname(base, -1, remote_host, remote_port, NULL);
    } else {
        ev = multi_socks_epoll_server_connect_hostname(base, -1, remote_host, remote_port, NULL);
    }

    if (ev == NULL) return;

    multi_socks_ev_setcb(event, NULL, NULL, ssl_event_cb, Context_new(event, ev));
    multi_socks_ev_setcb(ev, NULL, NULL, ssl_event_cb, Context_new(ev, event));
}

static int parse_remote_address(const char *address) {
    char *p = strrchr(address, ':');
    if (p == NULL || (++p[0] == '\0')) {
        LOGE("parse remote port failed");
        return -1;
    }
    p++;
    if (p[0] == '\0') {
        LOGE("parse remote port failed");
        return -1;
    }

    char *end = NULL;
    remote_port = (int) strtol(p, &end, 10);
    if (end == NULL || end[0] != '\0') {
        return -1;
    }

    remote_host = strndup(address, p - address - 1);
    return 0;
}

static void
socks5_auth_cb(MultiSocksEvent *ev, int rep, char *bind_addr, u_short bind_port, u_short kcp_key, void *ctx) {
    // connect to remote socks server
    if (ev == NULL) {
        Socks5Context_event_freed(ctx);
        return;
    }
    socks5_set_remote_event(ev, ctx);
}

static bool match_sub_domains(char *host) {
    ssize_t index = strlen(host) - 1;

    int domain_size = 0;
    int target_domain_size = 2;
    while (true) {
        while (host[index] != '.') {
            if (index == 0) {
                return false;
            }
            index--;
        }
        domain_size++;

        if (domain_size != target_domain_size) {
            index--;
            continue;
        }

        if (CHashSet_contains(g_sub_domain_set, host + index)) {
            return true;
        }
        index--;
    }
}

static bool match_reg_domains(const char *host) {
    bool result = false;
    CArrayList_FOR1(g_reg_domain_array, i, item, {
        regex_t *reg = item;
        if (regexec(reg, host, 0, NULL, 0) == 0) {
            result = true;
            break;
        }
    })

    return result;
}

static MultiSocksEvent *socks_remote_connect(char *host, int port, void *ctx) {
    // connect to remote socks server
    if (CHashSet_contains(g_full_domain_set, host) || match_sub_domains(host) || match_reg_domains(host)) {
        socks5_client_auth(g_base, host, port, socks5_auth_cb, ctx);
        return NULL;
    }

    LOGD("no need proxy: %s:%d", host, port);
    return multi_socks_epoll_server_connect_hostname(g_base, -1, host, port, ctx);
}

static int dot_count(char *str) {
    size_t len = strlen(str);
    int count = 0;
    for (int i = 0; i < len; ++i) {
        if (str[i] == '.') count++;
    }
    return count;
}

static void parse_config(char *config_path) {
    if (config_path == NULL) {
        return;
    }

    bool need_free_config_path = false;
    if (config_path[0] != '/') {
        char p[PATH_MAX];
        bzero(p, sizeof(p));

        strcpy(p, workd_dir);
        strcat(p, "/");
        strcat(p, config_path);
        config_path = strdup(p);
        need_free_config_path = true;
    }

    FILE *file = fopen(config_path, "r");

    if (file == NULL) {
        LOGE("fopen %s failed: errno = %d, err = %s", config_path, errno, strerror(errno));
        if (need_free_config_path) {
            free(config_path);
        }
        return;
    }

    char line[PATH_MAX + 1];
    while (fgets(line, sizeof(line), file) != NULL) {
        LOGD("read line: %s", line);
        size_t len = strlen(line);
        if (len >= 2 && line[len - 2] == '\r' && line[len - 1] == '\n') {
            line[len - 2] = '\0';
        } else if (len >= 1 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        len = strlen(line);
        if (len == 0) {
            continue;
        }

        if (line[0] == '!' || line[0] == '#') {
            continue;
        }

        if (strncmp(line, "*.", 2) == 0) {
            int c = dot_count(line + 2);
            if (c == 0) {
                LOGW("bad sub domain: %s", line);
                continue;
            }

            if (regexec(&g_domain_reg, line + 2, 0, NULL, 0) != 0) {
                LOGW("regexec failed: %s", line + 1);
                continue;
            }

            CHashSet_add(g_sub_domain_set, line + 1);
        } else if (line[0] == '^') {
            regex_t *reg = malloc(sizeof(regex_t));
            int reg_error_code = regcomp(reg, line + 1, (unsigned int) REG_NOSUB | (unsigned int) REG_ICASE |
                                                        (unsigned int) REG_EXTENDED | (unsigned int) REG_NEWLINE);
            if (reg_error_code != 0) {
                char err_msg[1024];
                bzero(err_msg, sizeof(err_msg));
                regerror(reg_error_code, &g_domain_reg, err_msg, sizeof(err_msg));
                LOGW("regcomp failed: line = %s, error = %s", line + 1, err_msg);
                free(reg);
                continue;
            }

            CArrayList_add(g_reg_domain_array, reg);
        } else {
            if (regexec(&g_domain_reg, line, 0, NULL, 0) != 0) {
                LOGW("regexec failed: %s", line);
                continue;
            }

            CHashSet_add(g_full_domain_set, line);
        }
    }

    if (need_free_config_path) {
        free(config_path);
    }
}

static const struct option long_options[] = {
        {"remote",     required_argument, NULL, 'r'},
        {"local",      required_argument, NULL, 'l'},
        {"ssl",        no_argument,       NULL, 's'},
        {"auth_clear", no_argument,       NULL, 'a'},
        {"username",   required_argument, NULL, 'u'},
        {"password",   required_argument, NULL, 'p'},
        {"config",     required_argument, NULL, 'c'},
        {"dns",        required_argument, NULL, 'd'},
        {"log",        required_argument, NULL, 0},
        {"help",       no_argument,       NULL, 'h'},
        {NULL, 0,                         NULL, 0},
};

static void usage() {
    printf("ssl_socks usage:\n"
           "--remote -r     : remote socks server, support socks5 over ssl\n"
           "--local -l      : local bind address\n"
           "--ssl -s        : remote socks is ssl\n"
           "--auth_clear -a : local socks need clear ssl or not, if set this argument you should add -u and -p\n"
           "--username -u   : socks server username\n"
           "--password -p   : socks server password\n"
           "--config -c     : proxy config path\n"
           "--dns -d        : dns server address\n"
           "--log           : log level: debug, info and error\n"
           "--help -h       : show this help\n");
}

/*
 * params
 *
 * -r remote address
 * -l local address
 * -s optional: remote is ssl socks if set
 * -a optional: remote socks need auth
 * -u optional: remote socks username
 * -p optional: remote socks password
 * -c optional: config of proxy to remote
 * -d optional: dns server
 * -h optional: help and exit
 *
 * */
int main(int argc, char **argv) {
    if (argc == 1) {
        usage();
        return -1;
    }
    workd_dir = dirname(argv[0]);
    multi_socks_epoll_server_set_log_level(SOCKS_LOG_INFO);
    char *ssl_addr = NULL;
    char *socket_addr = NULL;
    char *dns_server = "114.114.114.114";

    int opt;
    while ((opt = getopt_long(argc, argv, "r:l:sau:p:c:d:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'r':
                ssl_addr = strdup(optarg);
                break;
            case 'l':
                socket_addr = strdup(optarg);
                break;
            case 's':
                ssl_clear = true;
                break;
            case 'a':
                auth_clear = true;
                break;
            case 'u':
                socks5_username = strdup(optarg);
                break;
            case 'p':
                socks5_password = strdup(optarg);
                break;
            case 'c':
                g_sub_domain_set = CHashSet_new_with_size(1024);
                g_full_domain_set = CHashSet_new_with_size(1024);
                g_reg_domain_array = CArrayList_new();

                int reg_error_code = regcomp(&g_domain_reg,
                                             "^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$",
                                             (unsigned int) REG_NOSUB | (unsigned int) REG_ICASE |
                                             (unsigned int) REG_EXTENDED | (unsigned int) REG_NEWLINE);
                if (reg_error_code != 0) {
                    char err_msg[1024];
                    bzero(err_msg, sizeof(err_msg));
                    regerror(reg_error_code, &g_domain_reg, err_msg, sizeof(err_msg));
                    LOGE("regcomp failed: %s", err_msg);
                    return -1;
                }
                parse_config(optarg);
                break;
            case 'd':
                dns_server = strdup(optarg);
                break;
            case 0:
                if (strcasecmp(optarg, "debug") == 0) {
                    multi_socks_epoll_server_set_log_level(SOCKS_LOG_DEBUG);
                } else if (strcasecmp(optarg, "info") == 0) {
                    multi_socks_epoll_server_set_log_level(SOCKS_LOG_INFO);
                } else if (strcasecmp(optarg, "error") == 0) {
                    multi_socks_epoll_server_set_log_level(SOCKS_LOG_ERROR);
                }
                break;
            case 'h':
                usage();
                return 0;
            default:
                break;
        }
    }

    if (auth_clear) {
        if (socks5_username == NULL || socks5_password == NULL) {
            LOGE("socks5 need username and password");
            return -1;
        }
    }

    LOGI("ssl: %s; socket: %s\n", ssl_addr, socket_addr);

    if (parse_remote_address(ssl_addr) == -1) {
        LOGE("parse remote address (%s) failed", ssl_addr);
        return -1;
    }

    if (auth_clear) {
        if (ssl_clear) {
            socks5_client_init_ssl(remote_host, remote_port, socks5_username, socks5_password);
        } else {
            socks5_client_init(remote_host, remote_port, socks5_username, socks5_password);
        }
    }

    MultiSocksBase *base = multi_socks_ev_base_new();
    g_base = base;
    multi_socks_epoll_server_set_dns_server(base, dns_server);

    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (parse_address(socket_addr, (struct sockaddr *) &addr, &addr_len) == -1) {
        LOGE("parse address failed: %s", socket_addr);
        return -1;
    }

    if (!auth_clear) {
        multi_socks_ev_listen(base, ssl_clear_ev_conn, -1, (struct sockaddr *) &addr, addr_len, base);
    } else {
        socks5_event_listen_init(base, (struct sockaddr *) &addr, addr_len, NULL);

        char bind_addr[IPV4_LEN];
        in_addr_t ip = inet_addr("127.0.0.1");
        n_write_uint32_t_to_data(bind_addr, ntohl(ip), 0);
        socks5_set_bind_addr(SOCKS5_ATYPE_IPV4, bind_addr, IPV4_LEN);
        socks5_set_remote_connect_cb(socks_remote_connect);
    }

    return multi_socks_ev_loop(base);
}