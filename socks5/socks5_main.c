#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>

#ifdef __linux__
#include <mcheck.h>
#endif

#include "clib.h"
#include "socks5.h"
#include "log.h"
#include "args_parser.h"
#include "msl.h"

struct socks {
    int fd;
    int s_version;
    int s_type;
    struct sockaddr_storage remote_addr;
    int finish_handshake;
};

void handler(int sig) {

    void *array[10];
    size_t size;

    // get void*'s for all entries on the stack
    size = backtrace(array, 10);

    // print out all the frames to stderr
    fprintf(stderr, "Error: signal %d:", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);

    if (sig == SIGPIPE || sig == SIGBUS) {
        return;
    }
    exit(1);
}

int main(int argc, char const **argv) {
    if (argc < 3) {
        slog(SOCKS_LOG_DEBUG,
             "command: ./server 127.0.0.1 1080 -u[ername] username -p[assword] password -m -mh host -mp port -hi[heartbeat_interval] 10 -rt[read_timeout] 10 -wt[write_timeout] 10");
        exit(0);
    }

#ifdef __linux__
    mtrace();
#endif
    struct sigaction si;
    bzero(&si, sizeof(si));
    si.sa_handler = SIG_IGN;
    int sr = sigaction(SIGPIPE, &si, NULL);
    LOGI("sigaction result = %d", sr);
    // signal(SIGPIPE, SIG_IGN);
    Socks5Config *config = Socks5Config_new();
    set_log_level(SOCKS_LOG_DEBUG);

#ifdef USE_MSL
    if (has_param(argc, argv, "-m"))
    {
        socks5_config_set_cb(config, multi_socks_connect_to_remote);
        set_multi_socks_server((char *)parse_string(argc, argv, "-mh"), (char *)parse_string(argc, argv, "-mp"));
        multi_socks_set_auth_info((char *)parse_string(argc, argv, "-u"), (char *)parse_string(argc, argv, "-p"));
        multi_socks_set_heartbeat(parse_int(argc, argv, "-hi", 10));
    }
    else
#endif
    {
        socks5_add_auth_info(parse_string(argc, argv, "-u"), parse_string(argc, argv, "-p"));
        if (has_param(argc, argv, "-kcp")) {
            socks5_set_use_kcp(1);
            char addr[IPV4_LEN];
            in_addr_t ip = inet_addr("192.168.31.162");
            n_write_uint32_t_to_data(addr, ntohl(ip), 0);
            socks5_set_bind_addr(SOCKS5_ATYPE_IPV4, addr, IPV4_LEN);
        }
    }
    socks5_set_timeout(parse_int(argc, argv, "-rt", 30), parse_int(argc, argv, "-wt", 30));

    int r = socks5_start(argv[1], atoi(argv[2]), config);
    if (r != 0) {
        slog(SOCKS_LOG_DEBUG, "start socks server failed");
        return -1;
    }

    return -1;
}
