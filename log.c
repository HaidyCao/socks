#include "log.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

static int log_level = 0;

#ifdef __ANDROID__
#include <android/log.h>

void alog(int level, const char *fmt, ...) {
    if (level < log_level) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    int l = ANDROID_LOG_DEBUG;
    if (level == SOCKS_LOG_INFO) {
        l = ANDROID_LOG_INFO;
    } else if (level == SOCKS_LOG_WARNING) {
        l = ANDROID_LOG_WARN;
    } else if (level == SOCKS_LOG_ERROR) {
        l = ANDROID_LOG_ERROR;
    }
    __android_log_vprint(l, "event", fmt, ap);

    va_end(ap);
}
#endif

const char *log_level_to_string(int level) {
    switch (level) {
        case SOCKS_LOG_TRACE:
            return "TRACE";
        case SOCKS_LOG_DEBUG:
            return "DEBUG";
        case SOCKS_LOG_INFO:
            return "INFO";
        case SOCKS_LOG_ERROR:
            return "ERROR";
        case SOCKS_LOG_WARNING:
            return "WARNING";
        default:
            return "unknown";
    }
}

void set_log_level(int level) {
    log_level = level;
    if (log_level > SOCKS_LOG_WARNING)
        log_level = SOCKS_LOG_WARNING;
    else if (log_level < SOCKS_LOG_DEBUG)
        log_level = SOCKS_LOG_DEBUG;
}

int get_log_level() {
    return log_level;
}

void slog(int level, const char *fmt, ...) {
    if (level < log_level) {
        return;
    }

    time_t now_time = time(NULL);
    struct tm *l = localtime(&now_time);

    struct timeval t;
    gettimeofday(&t, NULL);

    printf("%04d-%02d-%02d %02d:%02d:%02d %03d %s: ", l->tm_year + 1900, l->tm_mon + 1, l->tm_mday, l->tm_hour,
           l->tm_min, l->tm_sec, (int) (t.tv_usec / 1000), log_level_to_string(level));

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);

    va_end(ap);
}
