#ifndef SOCKS5_CLIENT_H
#define SOCKS5_CLIENT_H

#include "socks5_base.h"
#include "../event/multi_socks_epoll_server.h"

typedef void (*socks5_client_auth_cb)(MultiSocksEvent *ev, int rep, char *bind_addr, u_short bind_port, u_short kcp_key,
                                      void *ctx);

typedef void (*socks5_client_transfer_data_close_cb)(MultiSocksEvent *local, void *ctx);

typedef void (*socks5_client_remote_read_cb)(MultiSocksEvent *ev, char *buf, size_t len, void *ctx);

const char *socks5_client_get_rep_string(int rep);

int socks5_client_init(const char *host, u_short port, const char *username, const char *password);

int socks5_client_init_ssl(const char *host, u_short port, const char *username, const char *password);

int socks5_client_auth(MultiSocksBase *base, char *host, u_short port, socks5_client_auth_cb cb, void *ctx);

/**
 * set remote read cb
 * @param remote
 * @param bind_addr
 * @param bind_port
 * @param kcp_key
 * @param cb
 * @param ctx
 * @return -1 failure
 */
int
socks5_client_set_remote_read_cb(MultiSocksEvent *remote, char *bind_addr, u_short bind_port, u_short kcp_key,
                                 socks5_client_remote_read_cb cb, void *ctx);

/**
 * write data to remote
 * @param remote
 * @param buf
 * @param len
 * @return -1 write failed, else return length of write to remote
 */
int
socks5_client_write_data_to_remote(MultiSocksEvent *remote, char *buf, size_t len);

/**
 * set 1 use kcp
 * @param kcp
 */
void socks5_client_set_use_kcp(int kcp);

/**
 * transfer data between local and remote
 * @param local local event
 * @param remote remove event
 * @param bind_addr socks5 binding address
 * @param bind_port socks5 binding port
 * @param kcp_key key of key or 0 not support kcp
 * @param cb transfer close callback
 * @param ctx ctx
 * @return -1: start transfer data filed
 */
int
socks5_client_transfer_data(MultiSocksEvent *local, MultiSocksEvent *remote, char *bind_addr, u_short bind_port,
                            u_short kcp_key, socks5_client_transfer_data_close_cb cb, void *ctx);

#endif // SOCKS5_CLIENT_H