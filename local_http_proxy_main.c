#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "local_dec_server.h"
#include "args_parser.h"

void handler(int sig)
{
    if (sig == SIGPIPE)
    {
        return;
    }
    void *array[10];
    size_t size;

    // get void*'s for all entries on the stack
    size = backtrace(array, 10);

    // print out all the frames to stderr
    fprintf(stderr, "Error: signal %d:", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}

int main(int argc, char const **argv)
{
    if (argc < 3)
    {
        LOGE("command: ./local_http_proxy 127.0.0.1 43128 -h host -p port");
        exit(0);
    }
    signal(SIGSEGV, handler);
    signal(SIGABRT, handler);
    signal(SIGPIPE, handler);

    set_log_level(SOCKS_LOG_DEBUG);
    set_remote_server(parse_string(argc, argv, "-h"), parse_string(argc, argv, "-p"));
    return start_local_server(argv[1], atoi(argv[2]));
}