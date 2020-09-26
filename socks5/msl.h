#ifndef MULTI_SOCKS_CLIENT_H
#define MULTI_SOCKS_CLIENT_H

#include "socks5.h"

#define CONNECT_OK 1
#define CONNECT_FAILED 0

#ifdef __cplusplus

extern "C"
{

#endif

    struct msl_context;
    typedef struct msl_context MslServerContext;
    void MslServerContext_arg(MslServerContext *context, void *arg);

    typedef void (*msl_connect_cb)(MslServerContext *ctx, int success, void *arg);
    typedef int (*msl_read_cb)(MslServerContext *ctx, char *data, size_t len, void *arg);

    void multi_socks_connect_to_remote(Socks5Context *context);
    void multi_socks_set_auth_info(char *username, char *password);
    void set_multi_socks_server(char *host, char *port);
    void multi_socks_set_heartbeat(int interval);
    void msl_connect(MultiSocksBase *base, char *host, int port, msl_connect_cb conn_cb, msl_read_cb read_cb, void *arg);
    int msl_write(MslServerContext *ctx, char *data, size_t len);
    int msl_close(MslServerContext *ctx);

#ifdef __cplusplus
}

#endif

#endif