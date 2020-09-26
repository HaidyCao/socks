#ifndef ARGS_PARSER
#define ARGS_PARSER

int has_param(int argc, char const **argv, const char *name);
const char *parse_string(int argc, char const **argv, const char *name);
int parse_int(int argc, char const **argv, const char *name, int def);

#endif