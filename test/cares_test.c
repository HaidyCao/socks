#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ares.h"

#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ares.h>
#include <pthread.h>

void dns_callback(void *arg, int status, int timeouts, struct hostent *host) //ares  处理完成，返回DNS解析的信息
{

    if (status == ARES_SUCCESS)
    {

        size_t i = 0;
        while (host->h_addr_list[i])
        {
            printf("i == %zu\n", i);
            printf("%s解析成功：%s\n", host->h_name, inet_ntoa(*(struct in_addr *)host->h_addr_list[i]));
            i++;
        }
    }
    else
        printf("解析失败：%d\n", status);
}

char *domain_list[] = {
    "www.baidu.com",
    "www.google.com",
    "hfuter.app",
    "caohaidi.cn",
    "github.com",
    NULL,
};

struct cares_test
{
    ares_channel channel;
    char *domain;
};

void sub_thread(void *p)
{
    struct cares_test *s = (struct cares_test *)p;
    ares_gethostbyname(s->channel, s->domain, AF_INET, dns_callback, NULL);
    free(s);
}

int pid = -1;
void main_loop(ares_channel channel)
{
    int nfds, count;
    fd_set readers, writers;
    struct timeval tv, *tvp;
    while (1)
    {
        FD_ZERO(&readers);
        FD_ZERO(&writers);
        nfds = ares_fds(channel, &readers, &writers); //获取ares channel使用的FD
        if (nfds == 0)
        {
            if (pid != -1)
            {
                continue;
            }

            // ares_gethostbyname(channel, "www.baidu.com", AF_INET, dns_callback, NULL);            // break;
            printf("nfds = %d\n", nfds);
            size_t i = 0;
            char *domain;
            while ((domain = domain_list[i]))
            {
                struct cares_test *s = (struct cares_test *)calloc(1, sizeof(struct cares_test));
                s->channel = channel;
                s->domain = domain;
                pthread_t t1;
                pid = pthread_create(&t1, NULL, (void *)&sub_thread, s);
                i++;
            }

            continue;
        }
        printf("nfds = %d\n", nfds);

        tvp = ares_timeout(channel, NULL, &tv);
        count = select(nfds, &readers, &writers, NULL, tvp); //将ares的SOCKET FD 加入事件循环
        ares_process(channel, &readers, &writers);           // 有事件发生 交由ares 处理

        printf("ares_process\n");
    }
}
int main(int argc, char **argv)
{
    int res;
    if (argc < 2)
    {
        printf("输入参数错误\n");
        return 1;
    }
    ares_channel channel; // 创建一个ares_channel
    if ((res = ares_init(&channel)) != ARES_SUCCESS)
    { // ares 对channel 进行初始化

        return 1;
    }
    ares_gethostbyname(channel, argv[1], AF_INET, dns_callback, NULL); //传递给c-ares channal 和 回调
    ares_gethostbyname(channel, argv[2], AF_INET, dns_callback, NULL); //传递给c-ares channal 和 回调
    main_loop(channel);                                                //主程序事件循环
    return 0;
}
