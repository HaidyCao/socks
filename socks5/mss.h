#ifndef MULTI_SOCKS_SERVER_H
#define MULTI_SOCKS_SERVER_H

#include "../lib/c_hex_utils.h"

void add_auth(char *username, char *password);
int mss_start(char *ip, int port);
void set_dns_server(const char *host);

#endif