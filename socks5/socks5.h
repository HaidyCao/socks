#ifndef SOCKS5_H
#define SOCKS5_H

#include "../event/multi_socks_epoll_server.h"
#include "socks5_base.h"

#ifdef __cplusplus

extern "C"
{

#endif

#define type_to_string(type) type == SOCKS_TYPE_CLIENT ? "Client" : (type == SOCKS_TYPE_REMOTE ? "Remote" : "Unknown")

/**
* callback of when need connect to remote
*/
typedef MultiSocksEvent *(*socks5_remote_connect_cb)(char *host, int port, void *ctx);

/**
 * setup custom remote callback
 * @param cb
 */
void socks5_set_remote_connect_cb(socks5_remote_connect_cb cb);

struct socks5_context;
typedef struct socks5_context Socks5Context;

void Socks5Context_event_freed(Socks5Context *socks5);

void Socks5Context_free(Socks5Context *socks5);

MultiSocksBase *socks5_context_get_base(Socks5Context *socks5);

void socks5_context_get_remote_address(Socks5Context *socks5, char **host, int *port);

MultiSocksEvent *socks5_context_get_ev(Socks5Context *socks5);

int socks5_context_set_ev(Socks5Context *socks5, MultiSocksEvent *ev);

int socks5_context_get_reply_data(Socks5Context *socks5, char **data, size_t *len);

struct socks5_config;
typedef struct socks5_config Socks5Config;

Socks5Config *Socks5Config_new();

void Socks5Config_free(Socks5Config *config);

typedef void (*socks5_connect_to_remote)(Socks5Context *socks5_server);

int socks5_config_set_cb(Socks5Config *config, socks5_connect_to_remote cb);

void socks5_set_timeout(int read_timeout, int write_timeout);

int socks5_add_auth_info(const char *username, const char *password);

/**
 * set use kcp
 * @param kcp
 */
void socks5_set_use_kcp(int kcp);

/**
 * set bind addr
 * @param type bind type
 * @param addr ipv4 ipv6 or domain
 * @param addr_len addr length
 * @return -1 failure
 */
int socks5_set_bind_addr(int type, char *addr, u_char addr_len);

int socks5_event_listen_init(MultiSocksBase *base, struct sockaddr *addr, socklen_t addr_len, Socks5Config *config);

#ifdef SOCKS_SSL
#include "openssl/ssl.h"

int socks5_event_ssl_listen_init(MultiSocksBase *base, struct sockaddr *addr, socklen_t addr_len, SSL_CTX *ssl_ctx, Socks5Config *config);
#endif

int socks5_event_init(MultiSocksBase *base, const char *ip, int port, Socks5Config *config);

void socks5_set_remote_event(MultiSocksEvent *event, void *ctx);

int socks5_start(const char *ip, int port, Socks5Config *config);

#ifdef __cplusplus
}

#endif

#endif