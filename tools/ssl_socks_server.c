//
// Created by Haidy on 2020/9/21.
//

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <stdbool.h>

#include "openssl/ssl.h"
#include "openssl/err.h"

#include "../log.h"
#include "../lib/clib.h"
#include "../socks5/socks5.h"

#define SSL_KEY_VAL     0
#define SSL_CERT_VAL    1

#define ARG_ADDRESS             "address"
#define ARG_SSL                 "ssl"
#define ARG_KEY_PATH            "key_path"
#define ARG_CERT_PATH           "cert_path"
#define ARG_USERNAME_PASSWORD   "up"
#define ARG_BIND_IP             "bind_ip"
#define ARG_KCP                 "kcp"
#define ARG_READ_TIMEOUT        "read_timeout"
#define ARG_WRITE_TIMEOUT       "read_timeout"
#define ARG_LOG                 "log"

#define STR_CONFIG  "config"
#define STR_HELP    "help"

static char *address = NULL;
static bool ssl = false;
static char *ssl_key_path = NULL;
static char *ssl_cert_path = NULL;
static SSL_CTX *ssl_ctx = NULL;
static char *bind_ip = NULL;
static int read_timeout = 0;
static int write_timeout = 0;

static const struct option long_options[] = {
        {ARG_ADDRESS,       required_argument, NULL, 'a'},
        {ARG_SSL,           no_argument,       NULL, 's'},
        {ARG_KEY_PATH,      required_argument, NULL, SSL_KEY_VAL},
        {ARG_CERT_PATH,     required_argument, NULL, SSL_CERT_VAL},
        {STR_CONFIG,        required_argument, NULL, 'c'},
        {ARG_KCP,           no_argument,       NULL, 'k'},
        {ARG_BIND_IP,       required_argument, NULL, 'b'},
        {ARG_READ_TIMEOUT,  required_argument, NULL, 'r'},
        {ARG_WRITE_TIMEOUT, required_argument, NULL, 'w'},
        {ARG_LOG,           required_argument, NULL, 'l'},
        {STR_HELP,          no_argument,       NULL, 'h'},

};

static MultiSocksBase *base;

static void usage() {
    printf("ssl_socks_server usage:\n"
           "\n"
           "\n");
}

static int parse_int_arg(char *arg) {
    if (arg == NULL) {
        LOGE("arg is null");
        exit(-1);
    }

    char *end = NULL;
    long ret = strtol(arg, &end, 10);
    if (end == NULL || end[0] != '\0') {
        LOGE("parse arg to int failed: %s", arg);
        exit(-1);
    }

    return (int) ret;
}

#define IS_ARG(arg) strncmp(line, arg, name_len) == 0

static void parse_line(const char *line) {
    // TODO: test
    char *s = strchr(line, ':');
    if (s == NULL) {
        return;
    }

    char *p = s;
    while (p[0] == ' ') {
        p++;
    }

    ssize_t name_len = s - line;
    char *value = p;

    if (IS_ARG(ARG_ADDRESS)) {
        address = strdup(value);
    } else if (IS_ARG(ARG_SSL)) {
        ssl = strcmp(value, "on") == 0;
    } else if (IS_ARG(ARG_KEY_PATH)) {
        ssl_key_path = strdup(value);
    } else if (IS_ARG(ARG_CERT_PATH)) {
        ssl_cert_path = strdup(value);
    } else if (IS_ARG(ARG_KCP)) {
        bool kcp = strcmp(value, "on") == 0;
        socks5_set_use_kcp(kcp);
    } else if (IS_ARG(ARG_USERNAME_PASSWORD)) {
        char username[PATH_MAX];
        bzero(username, sizeof(username));

        char *space_start = strchr(value, ' ');
        if (space_start == NULL) {
            LOGW("parse username password failed: %s", line);
            return;
        }

        strncpy(username, value, space_start - value);
        char *password = space_start;
        while (password[0] == ' ') {
            password++;
        }

        socks5_add_auth_info(username, password);
    } else if (IS_ARG(ARG_BIND_IP)) {
        bind_ip = strdup(optarg);
    } else if (IS_ARG(ARG_READ_TIMEOUT)) {
        read_timeout = parse_int_arg(value);
    } else if (IS_ARG(ARG_WRITE_TIMEOUT)) {
        write_timeout = parse_int_arg(value);
    } else {
        LOGI("unknown argument: %s", line);
    }
}

static void parse_config(const char *config_path) {
    if (config_path == NULL) {
        return;
    }

    FILE *file = fopen(config_path, "r");

    if (file == NULL) {
        LOGE("fopen %s failed: errno = %d, err = %s", config_path, errno, strerror(errno));
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

        parse_line(line);
    }
}

/**
 * entry of ssl_socks_server
 *
 * @param argc count of arguments
 * @param args
 * @return
 */
int main(int argc, char **argv) {
    if (argc == 1) {
        usage();
        return -1;
    }

    int opt;

    while ((opt = getopt_long(argc, argv, "a:sc:hb:kr:w:l:", long_options, NULL)) != -1) {
        LOGD("opt: %c", opt);
        switch (opt) {
            case 'a':
                address = strdup(optarg);
                break;
            case 's':
                ssl = true;
                break;
            case 'c':
                parse_config(optarg);
                break;
            case 'h':
                usage();
                return 0;
            case 'b':
                bind_ip = strdup(optarg);
                break;
            case 'k':
                socks5_set_use_kcp(true);
                break;
            case 'r':
                read_timeout = parse_int_arg(optarg);
                break;
            case 'w':
                write_timeout = parse_int_arg(optarg);
                break;
            case 'l':
                if (strcmp("debug", optarg) == 0) {
                    set_log_level(SOCKS_LOG_DEBUG);
                } else if (strcmp("info", optarg) == 0) {
                    set_log_level(SOCKS_LOG_INFO);
                } else if (strcmp("error", optarg) == 0) {
                    set_log_level(SOCKS_LOG_ERROR);
                }
                break;
            case SSL_KEY_VAL:
                ssl_key_path = strdup(optarg);
                break;
            case SSL_CERT_VAL:
                ssl_cert_path = strdup(optarg);
                break;
            default:
                LOGD("unknown argument: %d", opt);
                usage();
                return -1;
        }
    }

    // check address
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (parse_address(address, (struct sockaddr *) &addr, &addr_len) == -1) {
        LOGE("parse address failed: %s", address);
        return -1;
    }

    if (ssl) {
        if (ssl_cert_path == NULL || ssl_key_path == NULL) {
            LOGE("ssl key or cert path is empty");
            return -1;
        }

        SSL_library_init();
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        const SSL_METHOD *method;
        method = SSLv23_server_method();
        ssl_ctx = SSL_CTX_new(method);

        if (ssl_ctx == NULL) {
            LOGE("SSL_CTX_new failed");
            return -1;
        }

        SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

        if (SSL_CTX_use_certificate_file(ssl_ctx, ssl_cert_path, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, ssl_key_path, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }

    if (bind_ip) {
        if (strstr(bind_ip, ":")) {
            struct in6_addr ip;

            int bind_result = inet_pton(AF_INET6, bind_ip, &ip);
            if (bind_result == -1) {
                LOGE("parse bind_ip failed: %d, err: ", errno, strerror(errno));
                return -1;
            } else if (bind_result == 0) {
                LOGE("parse bind_ip failed: 0");
                return -1;
            }

            socks5_set_bind_addr(SOCKS5_ATYPE_IPV6, (char *) &ip, IPV6_LEN);
        } else {
            in_addr_t ip = inet_addr(bind_ip);
            socks5_set_bind_addr(SOCKS5_ATYPE_IPV4, (char *) &ip, IPV4_LEN);
        }
    }

    base = multi_socks_ev_base_new();
    socks5_set_timeout(read_timeout, write_timeout);
    if (ssl_ctx) {
        socks5_event_ssl_listen_init(base, (struct sockaddr *) &addr, addr_len, ssl_ctx, NULL);
    } else {
        socks5_event_listen_init(base, (struct sockaddr *) &addr, addr_len, NULL);
    }

    int r = multi_socks_ev_loop(base);
    LOGE("start socks server failed: %d", r);

    return 0;
}