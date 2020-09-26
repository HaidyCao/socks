#ifndef HTTP_PROXY_SERVER_H
#define HTTP_PROXY_SERVER_H

#include "log.h"

void set_ssl(const char *key_path, const char *cert_path);
void add_proxy_auth_info(const char *username, const char *password);
int start_http_server(const char *ip, int port);

#endif // HTTP_PROXY_SERVER_H