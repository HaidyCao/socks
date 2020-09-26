#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "args_parser.h"

int has_param(int argc, char const **argv, const char *name)
{
    int i;
    for (i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], name) == 0)
        {
            return 1;
        }
    }
    return 0;
}

const char *parse_string(int argc, char const **argv, const char *name)
{
    int i;
    for (i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], name) == 0)
        {
            if (i + 1 < argc)
            {
                return argv[i + 1];
            }
        }
    }
    return NULL;
}

int parse_int(int argc, char const **argv, const char *name, int def)
{
    const char *v = parse_string(argc, argv, name);
    if (v)
        return atoi(v);

    return def;
}
