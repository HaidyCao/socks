#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>

#include "clib.h"
#include "log.h"
#include "args_parser.h"
#include "mss.h"

void handler(int sig)
{

    void *array[10];
    size_t size;

    // get void*'s for all entries on the stack
    size = backtrace(array, 20);

    // print out all the frames to stderr
    fprintf(stderr, "Error: signal %d:", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);

    if (sig == SIGPIPE)
    {
        return;
    }
    exit(1);
}

int main(int argc, char const **argv)
{
    if (argc < 3)
    {
        slog(SOCKS_LOG_DEBUG, "command: ./mss 127.0.0.1 1080 -key_path key_path -cert_path cert_path -u[ername] username -p[assword] password");
        exit(0);
    }
    signal(SIGBUS, handler);
    signal(SIGSEGV, handler);
    signal(SIGABRT, handler);
    signal(SIGPIPE, handler);

    add_auth((char *)parse_string(argc, argv, "-u"), (char *)parse_string(argc, argv, "-p"));
    set_dns_server(parse_string(argc, argv, "-d"));
    // set_log_level(SOCKS_LOG_INFO);

    int r = mss_start((char *)argv[1], atoi(argv[2]));
    if (r != 0)
    {
        slog(SOCKS_LOG_DEBUG, "start socks server failed");
        return -1;
    }

    return -1;
}
