#ifndef MULTI_SOCKS_H
#define MULTI_SOCKS_H

#define MULTI_SOCKS_CMD_CONNECT 0x01
#define MULTI_SOCKS_CMD_WRITE 0x02
#define MULTI_SOCKS_CMD_CLOSE 0x03
#define MULTI_SOCKS_CMD_CONNECT_RESULT 0x04
#define MULTI_SOCKS_CMD_DRAIN 0x05
#define MULTI_SOCKS_CMD_FREE_DRAIN 0x06
#define MULTI_SOCKS_CMD_ERROR_MSG 0x07
#define MULTI_SOCKS_CMD_HEARTBEAT 0x08

#define MULTI_SOCKS_VERSION_1 1

#define MULTI_SOCKS_AUTH_TYPE_USERNAME_PASSWORD 0x02

struct multi_socks_packet
{
    char version;
    char cmd;
    unsigned short sequence;
    unsigned short p_len;
    char *host;
    unsigned short port;
    unsigned int session;
    unsigned short d_len;
    unsigned short sum;
    char *data;
};

typedef struct multi_socks_packet MultiSocksPacket;

unsigned short read_short(char *data, size_t offset);

int multi_socks_checksum_and_pack(MultiSocksPacket *packet, char *data);
int multi_socks_parse_and_verify_checksum(MultiSocksPacket *packet, char *data);

#endif