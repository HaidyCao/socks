#ifndef C_DNS_H
#define C_DNS_H

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>

#define C_DNS_QTYPE_A 1
#define C_DNS_QTYPE_NS 2
#define C_DNS_QTYPE_MD 3
#define C_DNS_QTYPE_MF 4
#define C_DNS_QTYPE_CNAME 5
#define C_DNS_QTYPE_SOA 6
#define C_DNS_QTYPE_MB 7
#define C_DNS_QTYPE_MG 8
#define C_DNS_QTYPE_MR 9
#define C_DNS_QTYPE_NULL 10
#define C_DNS_QTYPE_WKS 11
#define C_DNS_QTYPE_PTR 12
#define C_DNS_QTYPE_HINFO 13
#define C_DNS_QTYPE_MINFO 14
#define C_DNS_QTYPE_MX 15
#define C_DNS_QTYPE_TXT 16
#define C_DNS_QTYPE_AAAA 28

#define C_DNS_QTYPE_VALUE_AXFR 252
#define C_DNS_QTYPE_VALUE_MAILB 253
#define C_DNS_QTYPE_VALUE_MAILA 254
#define C_DNS_QTYPE_VALUE_ALL 255

#define C_DNS_CLASS_IN 1
#define C_DNS_CLASS_CS 2
#define C_DNS_CLASS_CH 3
#define C_DNS_CLASS_HS 4

ssize_t c_dns_pack(char *domain, char *buf, size_t buf_len, u_short type);
void c_dns_free_hostent(struct hostent *host);
int c_dns_parse_a(char *data, unsigned int len, struct hostent **host);
int c_dns_parse_first_ip(struct hostent *host, struct sockaddr *addr, size_t *addr_len, int port);

typedef int (*c_dns_ipv4_cb)(char *domain, struct in_addr *ip);
typedef int (*c_dns_ipv6_cb)(char *domain, struct in6_addr *ip);
int c_dns_gen_inet_response(char *data, size_t len, char **resp_data, size_t *resp_len, c_dns_ipv4_cb ipv4_cb, c_dns_ipv6_cb ipv6_cb);

#endif