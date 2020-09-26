#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "multi_socks.h"
#include "../log.h"
#include "c_hex_utils.h"

unsigned short read_short(char *data, size_t offset)
{
    unsigned short a = (((int)data[offset]) << 8) & 0xFF00;
    unsigned short b = (data[offset + 1]) & 0x00FF;
    return a | b;
}

static void write_short(char *data, int offset, unsigned short value)
{
    data[offset] = (char)((value >> 8) & 0x00FF);
    data[offset + 1] = (char)(value & (char)0xFF);
}

unsigned int read_int(char *data, size_t offset)
{
    unsigned int a = (((unsigned int)data[offset]) << 24) & 0xFF000000;
    unsigned int b = (((unsigned int)data[offset + 1]) << 16) & 0xFF0000;
    unsigned int c = (((unsigned int)data[offset + 2]) << 8) & 0xFF00;
    unsigned int d = (data[offset + 3]) & 0xFF;
    return a | b | c | d;
}

static void write_int(char *data, int offset, unsigned int value)
{
    data[offset] = (char)((value >> 24) & 0x00FF);
    data[offset + 1] = (char)((value >> 16) & 0x00FF);
    data[offset + 2] = (char)((value >> 8) & 0x00FF);
    data[offset + 3] = (char)(value & (char)0x00FF);
}

static long get_sum(char *buf, size_t offset, size_t len)
{
    long sum = 0;
    while (len > 1)
    {
        sum += (((short)read_short(buf, offset)) & 0xFFFF);
        offset += 2;
        len -= 2;
    }
    if (len > 0)
        sum += (buf[offset] & 0xFF) << 8;
    return sum;
}

static unsigned short checksum(long sum, char *buf, size_t offset, size_t len)
{
    sum += get_sum(buf, offset, len);
    while ((sum >> 16) > 0)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short)~sum;
}

static void packet_checksum(MultiSocksPacket *packet, char *data)
{
    packet->sum = checksum(0, data, 0, packet->p_len);
}

int multi_socks_checksum_and_pack(MultiSocksPacket *packet, char *data)
{
    if (packet == NULL || data == NULL)
        return -1;

    data[0] = packet->version;
    data[1] = packet->cmd;
    write_short(data, 2, packet->p_len);
    write_short(data, 4, packet->sequence);
    if (packet->host != NULL)
    {
        data[6] = strlen(packet->host);
        memcpy(data + 7, packet->host, data[6]);
    }
    else
        data[6] = 0;

    write_short(data, 7 + data[6], packet->port);
    LOGI("session = %x", packet->session);
    write_int(data, 7 + data[6] + 2, packet->session);
    hexDump(data + 7 + data[6] + 2, 4, 0);
    write_short(data, 7 + data[6] + 2 + 4, packet->d_len);
    write_short(data, 7 + data[6] + 2 + 4 + 2, 0);
    if (packet->data != NULL)
        memcpy(data + 7 + data[6] + 2 + 4 + 2 + 2, packet->data, packet->d_len);

    packet_checksum(packet, data);
    write_short(data, 7 + data[6] + 2 + 4 + 2, packet->sum);
    // hexDump(data, packet->p_len, 0);
    return 0;
}

int multi_socks_parse_and_verify_checksum(MultiSocksPacket *packet, char *data)
{
    if (packet == NULL || data == NULL)
        return 0;

    packet->version = data[0];
    packet->cmd = data[1];
    packet->p_len = read_short(data, 2);
    packet->sequence = read_short(data, 4);
    LOGD("host len = %d", data[6]);
    hexDump(data + 7, data[6], 0);

    if (data[6] > 0 && packet->host == NULL)
        packet->host = strndup(data + 7, data[6]);
    packet->port = read_short(data, 7 + data[6]);
    packet->session = read_int(data, 7 + data[6] + 2);
    hexDump(data + 7 + data[6] + 2, 4, 0);
    packet->d_len = read_short(data, 7 + data[6] + 2 + 4);
    packet->sum = read_short(data, 7 + data[6] + 2 + 4 + 2);
    packet->data = data + 7 + data[6] + 2 + 4 + 2 + 2;

    unsigned short sum = packet->sum;
    write_short(data, 7 + data[6] + 2 + 4 + 2, 0);
    packet_checksum(packet, data);
    LOGD("packet len = %d, getSum = %x, checksum = %x", packet->p_len, sum, packet->sum);
    int result = sum == packet->sum;

    if (!result)
    {
        hexDump(data, packet->p_len, 0);
    }
    return result;
}