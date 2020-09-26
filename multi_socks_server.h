#ifndef MULTI_SOCKS_SERVER_H
#define MULTI_SOCKS_SERVER_H

void add_auth(char *username, char *password);
int mss_start(char *ip, int port);

#endif