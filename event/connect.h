//
// Created by haidy on 2020/7/15.
//

#ifndef SOCKS_CONNECT_H
#define SOCKS_CONNECT_H

MultiSocksEvent *
multi_socks_epoll_server_connect_internal(MultiSocksBase *base, MultiSocksEvent *ev, int fd, int fd_type,
                                          struct sockaddr *addr, size_t addr_len, int ssl, void *ctx);

#endif //SOCKS_CONNECT_H
