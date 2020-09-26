#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "c_array.h"
#include "c_hash_map.h"
#include "multi_socks.h"

void test_array()
{
    int a = 1;
    int b = 2;
    int c = 3;
    Array array;
    init_array(&array);
    array_add(&array, &a);
    array_add(&array, &b);
    array_add(&array, &c);

    array_remove(&array, 1);

    int i;
    for (i = 0; i < array.len; i++)
    {
        int *v = (int *)array_get(&array, i);
        printf("v = %d\n", *v);
    }

    array_free(&array);
    printf("free array \n");
}

void test_hash_map()
{
    CHashMap hash_map;
    bzero(&hash_map, sizeof(CHashMap));
    c_hash_map_init(&hash_map);
    printf("c_hash_map_init\n");

    const char *a = "a";
    const char *b = "bb";
    const char *c = "ccc";
    const char *d = "dddd";

    c_hash_map_put(&hash_map, "aaaaaa", (void *)a);
    c_hash_map_put(&hash_map, "bbbbbb", (void *)b);
    c_hash_map_put(&hash_map, "cccccc", (void *)c);
    c_hash_map_put(&hash_map, "dddddd", (void *)d);
    printf("c_hash_map_add finished\n");

    C_HASH_MAP_FOR((&hash_map), {
        printf("node = %p, key = %s, value = %s\n", node, node->key, node->value);
    });

    c_hash_map_remove(&hash_map, "cccccc", 0);
    printf("\n");

    C_HASH_MAP_FOR((&hash_map), {
        printf("node = %p, key = %s, value = %s\n", node, node->key, node->value);
    });

    printf("has key(aaaaaa) = %d\n", c_hash_map_has(&hash_map, "aaaaaa"));
    printf("has key(cccccc) = %d\n", c_hash_map_has(&hash_map, "cccccc"));

    printf("map.count = %d\n", hash_map.count);
    c_hash_map_clear(&hash_map);
    printf("map.count = %d\n", hash_map.count);

    c_hash_map_free(&hash_map);
}

static void test_multi_socks_checksum()
{
    printf("test_multi_socks_checksum\n");
    MultiSocksPacket packet;
    bzero(&packet, sizeof(MultiSocksPacket));

    const char *data = "hello world";

    packet.version = 1;
    packet.d_len = strlen(data);
    packet.data = data;

    if (multi_socks_checksum(&packet) == -1)
    {
        printf("multi_socks_checksum error.\n");
        exit(0);
    }

    printf("checksum = %d\n", packet.sum);
    if (multi_socks_verify_checksum(&packet) == 0)
    {
        printf("new checksum = %d\n", packet.sum);
        exit(0);
    }
    printf("test_multi_socks_checksum success\n");
}

int main(int argc, char **argv)
{
    test_array();
    test_hash_map();
    test_multi_socks_checksum();

    return 0;
}