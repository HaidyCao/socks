#ifndef MULTI_SOCKS_CLIENT_H
#define MULTI_SOCKS_CLIENT_H

#include "socks5.h"

void multi_socks_connect_to_remote(Socks5Context *context);
void multi_socks_set_auth_info(char *username, char *password);
void set_multi_socks_server(char *host, char *port);

#endif