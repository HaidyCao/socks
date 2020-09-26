#ifndef CLIB_H
#define CLIB_H

#include <sys/socket.h>

#ifdef __APPLE__

#include <netinet/in.h>

#elif __linux__ || __ANDROID__
#include <linux/in6.h>
#endif

#include <arpa/inet.h>

#ifndef CLIB_ADDR
#define CLIB_ADDR
struct clib_addr {
    char ip[128];
    int port;
};

#endif

void print_address(struct sockaddr_storage *addr);

char *sockaddr_to_string(struct sockaddr *addr, char *s, int size);

int parse_clib_addr(struct sockaddr *addr, struct clib_addr *out);

char *trim(char *str);

int str_has_prefix(const char *str, const char *pre);

int str_has_suffix(const char *str, const char *suf);

int parse_address(const char *address, struct sockaddr *addr, socklen_t *len);

int addr_in_to_addr_in6(struct sockaddr_in *addr_in, struct sockaddr_in6 *addr_in6);

int addr_in6_to_addr_in(struct sockaddr_in6 *addr_in6, struct sockaddr_in *addr_in);

int ipv4_to_int(char ip[4]);

char *ipv6_to_string(char ip[16]);

void n_write_u_short_to_data(char *data, u_short v, size_t offset);

void n_write_uint32_t_to_data(char *data, uint32_t v, size_t offset);

u_int16_t ntohs_by_data(char *data, size_t offset);

int str_is_ipv4(const char *str);

time_t get_current_millisecond();

#endif /* CLIB_H */