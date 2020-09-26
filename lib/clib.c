#include <stdio.h>

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stddef.h>

#include "clib.h"

#define DLL_PUBLIC __attribute__((visibility("default")))

int stoi(const char *str, int *i) {
    char flag = '+';
    long res = 0;

    if (*str == '-') {
        ++str;
        flag = '-';
    }

    while (*str >= 48 && *str < 57) {
        res = 10 * res + *str++ - 48;
    }

    if (*str != '\0') {
#ifdef CLIB_LOG
        printf("str = %s\n", str);
#endif
        return -1;
    }

    if (flag == '-') {
        res = -res;
    }

    *i = res;
    return 0;
}

void print_address(struct sockaddr_storage *addr) {
    char ip[64];
    if (addr->ss_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *) addr;
        if (inet_ntop(in->sin_family, &in->sin_addr, ip, sizeof(ip)) != NULL) {
            printf("ip = %s, port = %d\n", ip, htons(in->sin_port));
        }
    } else if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *in = (struct sockaddr_in6 *) addr;
        if (inet_ntop(in->sin6_family, &in->sin6_addr, ip, sizeof(ip)) != NULL) {
            printf("ip = %s, port = %d\n", ip, htons(in->sin6_port));
        }
    }
}

char *sockaddr_to_string(struct sockaddr *addr, char *s, int size) {
    static char ip[128];
    bzero(ip, sizeof(ip));
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *) addr;
        if (inet_ntop(in->sin_family, &in->sin_addr, ip, sizeof(ip)) != NULL) {
            if (s && size >= strlen(ip)) {
                sprintf(s, "%s:%d", ip, htons(in->sin_port));
                return s;
            } else {
                sprintf(ip, "%s:%d", ip, htons(in->sin_port));
                return ip;
            }
        }
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in = (struct sockaddr_in6 *) addr;
        if (inet_ntop(in->sin6_family, &in->sin6_addr, ip, sizeof(ip)) != NULL) {
            if (s && size >= strlen(ip)) {
                sprintf(s, "%s:%d", ip, htons(in->sin6_port));
                return s;
            } else {
                sprintf(ip, "%s:%d", ip, htons(in->sin6_port));
                return ip;
            }
        }
    }
    return NULL;
}

int parse_clib_addr(struct sockaddr *addr, struct clib_addr *out) {
    if (out == NULL) {
        return -1;
    }
    bzero(out->ip, sizeof(out->ip));
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *) addr;
        if (inet_ntop(in->sin_family, &in->sin_addr, out->ip, sizeof(out->ip)) != NULL) {
            out->port = htons(in->sin_port);
            return 0;
        }
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in = (struct sockaddr_in6 *) addr;
        if (inet_ntop(in->sin6_family, &in->sin6_addr, out->ip, sizeof(out->ip)) != NULL) {
            out->port = htons(in->sin6_port);
            return 0;
        }
    }
    return -1;
}

int str_has_prefix(const char *str, const char *pre) {
    return strncmp(str, pre, strlen(pre)) == 0;
}

int str_has_suffix(const char *str, const char *suf) {
    int str_len = strlen(str);
    int suf_len = strlen(suf);
    if (suf_len > str_len) {
        return 0;
    }
    str += (str_len - suf_len);

    return strcmp(str, suf) == 0;
}

DLL_PUBLIC
int addr_in_to_addr_in6(struct sockaddr_in *addr_in, struct sockaddr_in6 *addr_in6) {
    char ipv4[16];
    bzero(ipv4, sizeof(ipv4));
    if (inet_ntop(AF_INET, &addr_in->sin_addr, ipv4, sizeof(ipv4)) != NULL) {
        char *fmt = "::ffff:%s";
        char ipv6[64];
        bzero(ipv6, sizeof(ipv6));

        sprintf(ipv6, fmt, ipv4);
        if (inet_pton(AF_INET6, ipv6, &addr_in6->sin6_addr) != 0) {
            addr_in6->sin6_port = addr_in->sin_port;
            addr_in6->sin6_family = AF_INET6;
            return 0;
        }
    }
    return -1;
}

DLL_PUBLIC
int addr_in6_to_addr_in(struct sockaddr_in6 *addr_in6, struct sockaddr_in *addr_in) {
    char ip[64];
    if (inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip, sizeof(ip)) != NULL) {
        char *prefix = "::ffff:";
        if (str_has_prefix(ip, prefix)) {
            char *ipv4 = ip + strlen(prefix);

            if (inet_pton(AF_INET, ipv4, &addr_in->sin_addr) != 0) {
                addr_in->sin_family = AF_INET;
                addr_in->sin_port = addr_in6->sin6_port;
                return 0;
            }
        }
    }
    return -1;
}

DLL_PUBLIC
int parse_address(const char *addr_str, struct sockaddr *addr, socklen_t *len) {
    if (*len < sizeof(struct sockaddr_in)) {
        return -1;
    }

    char *port_str;
    if (*addr_str == '[') {
        addr_str++;
        if ((port_str = strstr(addr_str, "]:")) != NULL) {
            size_t domain_len = strlen(addr_str) - strlen(port_str);
            char domain[domain_len + 1];
            strncpy(domain, addr_str, domain_len);
            domain[domain_len] = '\0';

            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) addr;
            port_str += 2;
            if (inet_pton(AF_INET6, domain, &addr_in6->sin6_addr) == 0) {
#ifdef CLIB_LOG
                printf("parse ipv6 address failed\n");
#endif
                return -1;
            }

            char *end = NULL;
            long p = strtol(port_str, &end, 10);
            if (end == NULL || end[0] != '\0') {
                return -1;
            }

            uint16_t port = (uint16_t) p;

            if (port <= 0 || port > 65535) {
                memset(&addr_in6->sin6_addr, '\0', sizeof(addr_in6->sin6_addr));
                return -1;
            }
            addr_in6->sin6_family = AF_INET6;
            addr_in6->sin6_port = ntohs(port);
            *len = sizeof(struct sockaddr_in6);
            return AF_INET6;
        }
    } else if ((port_str = strstr(addr_str, ":")) != NULL) {
        size_t domain_len = strlen(addr_str) - strlen(port_str);
        char domain[domain_len + 1];
        strncpy(domain, addr_str, domain_len);
        domain[domain_len] = '\0';

        in_addr_t ipv4 = inet_addr(domain);
        if (ipv4 != INADDR_NONE) {
            port_str++;

            char *end = NULL;
            long p = strtol(port_str, &end, 10);
            if (end == NULL || end[0] != '\0') {
                return -1;
            }

            uint16_t port = (uint16_t) p;
            if (port > 0 && port <= 65535) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
                addr_in->sin_family = AF_INET;
                addr_in->sin_port = ntohs(port);
                addr_in->sin_addr.s_addr = ipv4;
                *len = sizeof(struct sockaddr_in);
                return AF_INET;
            } else {
                // #ifdef CLIB_LOG
                printf("stoi failed: %s\n", port_str);
                // #endif
                return -1;
            }
        }
    }
    return -1;
}

//去除尾部空格
char *rtrim(char *str) {
    if (str == NULL || *str == '\0') {
        return str;
    }

    ssize_t len = strlen(str);
    char *p = str + len - 1;
    while (p >= str && (p[0] == '\r' || p[0] == '\n' || p[0] == ' ' || p[0] == '\t')) {
        *p = '\0';
        --p;
    }

    return str;
}

//去除首部空格
char *ltrim(char *str) {
    if (str == NULL || *str == '\0') {
        return str;
    }

    int len = 0;
    char *p = str;
    while (*p != '\0' && (p[0] == '\r' || p[0] == '\n' || p[0] == ' ' || p[0] == '\t')) {
        ++p;
        ++len;
    }

    memmove(str, p, strlen(str) - len + 1);

    return str;
}

//去除首尾空格
char *trim(char *str) {
    str = rtrim(str);
    str = ltrim(str);

    return str;
}

int ipv4_to_int(char ip[4]) {
    int a = (ip[0] & (int) 0xFF) << 0;
    int b = (ip[1] & (int) 0xFF) << 8;
    int c = (ip[2] & (int) 0xFF) << 16;
    int d = (ip[3] & (int) 0xFF) << 24;

    return a | b | c | d;
}

#define IPV6_LEN 16
const static char *hexDigit = "0123456789abcdef";

// Convert i to a hexadecimal string. Leading zeros are not printed.
static void append_hex(char *dst, int *index, int i) {
    if (i == 0) {
        dst[*index] = '0';
        (*index)++;
        return;
    }
    int j;
    for (j = 7; j >= 0; j--) {
        int v = i >> (uint) j * 4;
        if (v > 0) {
            dst[*index] = hexDigit[v & 0xf];
            (*index)++;
        }
    }
}

char *ipv6_to_string(char ip[16]) {
    int e0 = -1;
    int e1 = -1;

    size_t i;
    for (i = 0; i < IPV6_LEN; i += 2) {
        int j = i;
        while (j < IPV6_LEN && ip[j] == 0 && ip[j + 1] == 0) {
            j += 2;
        }
        if (j > i && j - i > e1 - e0) {
            e0 = i;
            e1 = j;
            i = j;
        }
    }

    // The symbol "::" MUST NOT be used to shorten just one 16 bit 0 field.
    if (e1 - e0 <= 2) {
        e0 = -1;
        e1 = -1;
    }

    size_t max_len = strlen("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    char *ip_str = (char *) malloc(max_len);
    bzero(ip_str, max_len);
    int index = 0;

    for (i = 0; i < IPV6_LEN; i += 2) {
        if (i == e0) {
            ip_str[index] = ':';
            ip_str[index + 1] = ':';
            index += 2;

            i = e1;
            if (i >= IPV6_LEN) {
                break;
            }
        } else if (i > 0) {
            ip_str[index] = ':';
            index++;
        }
        append_hex(ip_str, &index, (((uint) ip[i]) << 8) | (uint) ip[i + 1]);
    }
    return ip_str;
}

void n_write_u_short_to_data(char *data, u_short v, size_t offset) {
    data[offset] = (char) ((u_char) (v >> 8u) & (u_char) 0xFF);
    data[offset + 1] = (char) (v & (u_char) 0xFF);
}

void n_write_uint32_t_to_data(char *data, uint32_t v, size_t offset) {
    data[offset] = (char) ((v >> 24u) & (u_char) 0xFF);
    data[offset + 1] = (char) ((v >> 16u) & (u_char) 0xFF);
    data[offset + 2] = (char) ((v >> 8u) & (u_char) 0xFF);
    data[offset + 3] = (char) (v & (u_char) 0xFF);
}

u_int16_t ntohs_by_data(char *data, size_t offset) {
    uint16_t a = (u_int16_t) (((u_int16_t) data[offset]) << 8u) & (u_int16_t) 0xFF00;
    uint16_t b = ((u_int16_t) data[offset + 1]) & (u_int16_t) 0xFF;

    return a | b;
}

int str_is_ipv4(const char *str) {
    int a, b, c, d;
    if (4 == sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d)) {
        if ((a >= 0 && a < 256) && (b >= 0 && b < 256) && (c >= 0 && c < 256) && (d >= 0 && d < 256)) {
            return 1;
        }
    }
    return 0;
}

time_t get_current_millisecond() {
    struct timeval t;
    gettimeofday(&t, NULL);
    return t.tv_sec * 1000 + t.tv_usec / 1000;
}