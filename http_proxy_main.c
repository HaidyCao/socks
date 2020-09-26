#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "http_proxy_server.h"
#include "log.h"
#include "args_parser.h"

void handler(int sig)
{
  if (sig == SIGPIPE)
    return;

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
    LOGE("command: ./http_proxy 127.0.0.1 3128 -key_path key_path -cert_path cert_path -u[ername] username -p[assword] password");
    exit(0);
  }
  signal(SIGSEGV, handler);
  signal(SIGABRT, handler);
  signal(SIGPIPE, handler);

  int log_level = SOCKS_LOG_DEBUG;
  const char *l = parse_string(argc, argv, "-l");
  if (l != NULL)
    log_level = atoi(l);

  set_log_level(log_level);

  set_ssl(parse_string(argc, argv, "-key_path"), parse_string(argc, argv, "-cert_path"));
  add_proxy_auth_info(parse_string(argc, argv, "-u"), parse_string(argc, argv, "-p"));
  start_http_server(argv[1], atoi(argv[2]));
  return 0;
}