#include <string.h>
#include <stdio.h>

#include <stdlib.h>

#include "event2/util.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/event.h"
#include "event2/listener.h"
#include "event2/dns.h"
#include "event2/event-config.h"

#include "clib.h"
#include "proxy_ssl.h"
#include "http_proxy_server.h"
#include "chromiumbase64.h"
#include "c_hash_map.h"

#define TYPE_CLIENT 0
#define TYPE_REMOTE 1

#define MAX_OUTPUT (512 * 1024)

#define RFC_7230 "rfc_7230"
#define RFC_7231 "rfc_7231"

#define RFC_7231_OK_RESPONSE "HTTP/1.1 200 Connection Established\r\n\r\n"

#define HTTP_PROXY_STATUS_REQUEST 0
#define HTTP_PROXY_STATUS_RESPONSE 1
#define HTTP_PROXY_STATUS_OK 2
#define HTTP_PROXY_STATUS_FINISHING 3
#define HTTP_PROXY_STATUS_FINISHED 4

#define PROXY_TYPE_CONNECT "CONNECT"

#define MIME_WRAP "\r\n"

#define HTTP_HEADER_HOST "Host: "
#define HTTP_HEADER_PROXY_AUTH "Proxy-Authorization: "
#define HTTP_HEADER_CONTENT_LENGTH "Content-Length: "
#define HTTP_HEADER_TRANSFER_ENCODING "Transfer-Encoding: "
#define HTTP_HEADER_PROXY_AUTHENTICATE "Proxy-Authenticate: "
#define HTTP_HEADER_WWW_AUTHENTICATE_BASIC "WWW-Authenticate: Basic"

#define HTTP_AUTH_BASIC "Basic"
#define HTTP_HEADER_CHUNKED "Transfer-Encoding: chunked"

#define PROXY_AUTH_RESULT_OK 0
#define PROXY_AUTH_RESULT_FAILED 1
#define PROXY_AUTH_RESULT_NEED_AUTH 2

#define HTTP_REQUEST_DEFAULT_LENGTH -3

#define PRINT_HTTP_PROXY_CONN(conn)                                                                     \
    {                                                                                                   \
        if (conn)                                                                                       \
            LOGI("type = %s; status = %d; host = %s", conn_type(conn->type), conn->status, conn->host); \
    }

static struct event_base *base;
struct evconnlistener *listener;
static struct evdns_base *dns_base;

static int use_ssl;
SSL_CTX *ssl_ctx;

const struct timeval connect_timeout = {60 * 5, 0};

struct http_proxy_conn
{
    int type;
    int status;

    char *host;
    char *remote_host;
    struct bufferevent *bev;

    char *new_header;
    int new_header_len;
    int content_length;
    int write_body_length;

    int auth_result;
    const char *rfc;

    struct http_proxy_conn *partner;
};

struct proxy_auth_info
{
    char *username;
    char *password;
};

typedef struct proxy_auth_info ProxyAuthInfo;

static CHashMap *auth_info_map;

static void connect_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *ctx);
static void event_cb(struct bufferevent *bev, short what, void *ctx);
static void socks_read_cb(struct bufferevent *bev, void *ctx);
static void socks_write_cb(struct bufferevent *bev, void *ctx);
static void write_data_to_remote(struct http_proxy_conn *conn);

static char *conn_type(int t)
{
    if (t == TYPE_CLIENT)
    {
        return "Client";
    }
    else if (t == TYPE_REMOTE)
    {
        return "Remote";
    }
    else
    {
        return "Unknown Type";
    }
}

static void free_http_proxy_conn(void *ctx)
{
    LOGD("");
    struct http_proxy_conn *conn = (struct http_proxy_conn *)ctx;
    if (conn == NULL)
    {
        return;
    }

    if (conn->bev != NULL)
    {
        bufferevent_free(conn->bev);
        conn->bev = NULL;
    }

    free(conn->host);
    conn->host = NULL;

    free(conn->new_header);
    conn->new_header = NULL;

    conn->status = HTTP_PROXY_STATUS_FINISHED;
}

static int need_auth()
{
    return auth_info_map != NULL && auth_info_map->count > 0;
}

static int proxy_auth(char *line)
{
    char *value = line + strlen(HTTP_HEADER_PROXY_AUTH);
    if (str_has_prefix(value, HTTP_AUTH_BASIC " "))
    {
        // basic
        char *base64 = value + strlen(HTTP_AUTH_BASIC) + 1;
        int base64_len = strlen(base64);
        char username_password[chromium_base64_decode_len(base64_len)];
        int len = chromium_base64_decode(username_password, base64, base64_len);
        if (len == MODP_B64_ERROR)
        {
            LOGI("decode base failed");
            return PROXY_AUTH_RESULT_FAILED;
        }
        LOGI("base decode: %s", username_password);
        char *pwd = strrchr(username_password, ':');
        if (pwd == NULL)
        {
            LOGI("auth failed: password is NULL");
            return PROXY_AUTH_RESULT_FAILED;
        }

        pwd[0] = '\0';
        pwd++;

        ProxyAuthInfo *auth_info = (ProxyAuthInfo *)c_hash_map_get(auth_info_map, username_password);
        if (auth_info == NULL || strcmp(auth_info->password, pwd) != 0)
        {
            LOGI("auth failed: username = %s, password = %s", username_password, pwd);
            return PROXY_AUTH_RESULT_FAILED;
        }
        // if (strcmp(username_password, proxy_username) != 0 || strcmp(pwd, proxy_password) != 0)
        // {
        //     LOGI("auth failed: username = %s, password = %s", username_password, pwd);
        //     return PROXY_AUTH_RESULT_FAILED;
        // }
        return PROXY_AUTH_RESULT_OK;
    }

    LOGD("unsupport auth type: %s", value);
    return PROXY_AUTH_RESULT_FAILED;
}

static void drained_writecb(struct bufferevent *bev, void *ctx)
{
    LOGD("");
    struct http_proxy_conn *conn = (struct http_proxy_conn *)ctx;

    /* We were choking the other side until we drained our outbuf a bit.
	 * Now it seems drained. */
    bufferevent_setcb(bev, socks_read_cb, socks_write_cb, event_cb, conn);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    if (conn->partner && conn->partner->bev)
        bufferevent_enable(conn->partner->bev, EV_READ);
}

static void socks_read_cb(struct bufferevent *bev, void *ctx)
{
    LOGD("");
    struct http_proxy_conn *conn = (struct http_proxy_conn *)ctx;
    if (conn->type == TYPE_CLIENT && conn->status == HTTP_PROXY_STATUS_REQUEST)
    {
        struct evbuffer *bev_buffer = bufferevent_get_input(conn->bev);
        size_t len = evbuffer_get_length(bev_buffer);
        int drain_size = 0;
        if (len > 0)
        {
            char data[len + 1];
            bzero(data, sizeof(data));
            if (evbuffer_copyout(bev_buffer, data, len) != len)
            {
                LOGD("not read all data failed: errno = %d; %s", errno, strerror(errno));
                return;
            }

            if (!str_has_suffix(data, "\r\n\r\n"))
            {
                LOGD("we need read a empty line");
                return;
            }

            char *buffer = data;
            char *tmp = "";
            conn->auth_result = need_auth() ? PROXY_AUTH_RESULT_NEED_AUTH : PROXY_AUTH_RESULT_OK;
            if (str_has_prefix(data, PROXY_TYPE_CONNECT))
            {
                conn->rfc = RFC_7231;
                while ((tmp = strstr(buffer, MIME_WRAP)))
                {
                    int line_len = strlen(buffer) - strlen(tmp);
                    drain_size += line_len + 2;
                    char line[line_len + 1];
                    bzero(line, sizeof(line));
                    memcpy(line, buffer, line_len);
                    LOGD("line = %s", line);
                    buffer = tmp + 2;

                    // parse line
                    if (str_has_prefix(line, PROXY_TYPE_CONNECT))
                    {
                        char *address = trim(line + strlen(PROXY_TYPE_CONNECT));
                        char *split = strstr(address, " ");
                        if (split == NULL)
                            conn->remote_host = strdup(address);
                        else
                            conn->remote_host = strndup(address, strlen(address) - strlen(split));

                        LOGI("remote host = %s, rfc = %s", conn->remote_host, RFC_7231);
                    }
                    else if (str_has_prefix(line, HTTP_HEADER_PROXY_AUTH) && need_auth())
                    {
                        LOGD("ref = %s start auth", conn->rfc);
                        conn->auth_result = proxy_auth(line);
                        if (conn->auth_result == PROXY_AUTH_RESULT_FAILED)
                        {
                            free_http_proxy_conn(conn);
                            free_http_proxy_conn(conn->partner);
                            return;
                        }
                    }
                }
            }
            else
            {
                // read remote address and remove auth header
                conn->rfc = RFC_7230;
                conn->content_length = HTTP_REQUEST_DEFAULT_LENGTH;
                char *new_header = (char *)malloc(len);
                bzero(new_header, len);
                char *new_header_tmp = new_header;

                char *url;
                while ((tmp = strstr(buffer, MIME_WRAP)))
                {
                    int line_len = strlen(buffer) - strlen(tmp);
                    drain_size += line_len + 2;
                    char line[line_len + 1];
                    bzero(line, sizeof(line));

                    memcpy(line, buffer, line_len);
                    LOGD("line = %s", line);
                    buffer = tmp + 2;

                    if (str_has_prefix(line, HTTP_HEADER_HOST))
                    {
                        LOGD("parse remote address");
                        char *address = line + strlen(HTTP_HEADER_HOST);
                        if (strstr(address, ":") == NULL)
                        {
                            char *host;
                            asprintf(&host, "%s:80", address);
                            conn->remote_host = host;
                        }
                        else
                            conn->remote_host = strdup(address);

                        LOGI("remote host = %s, rfc = %s", conn->remote_host, RFC_7230);
                    }
                    else if (str_has_prefix(line, HTTP_HEADER_PROXY_AUTH) && need_auth())
                    {
                        LOGD("ref = %s start auth", conn->rfc);
                        conn->auth_result = proxy_auth(line);
                        if (conn->auth_result == PROXY_AUTH_RESULT_FAILED)
                        {
                            free_http_proxy_conn(conn);
                            free_http_proxy_conn(conn->partner);
                            return;
                        }
                        continue;
                    }
                    else if (str_has_prefix(line, HTTP_HEADER_CONTENT_LENGTH))
                    {
                        conn->content_length = atoi(line + strlen(HTTP_HEADER_CONTENT_LENGTH));
                    }

                    if (line_len > 0)
                    {
                        memcpy(new_header_tmp, line, line_len);
                        new_header_tmp += line_len;
                    }

                    memcpy(new_header_tmp, MIME_WRAP, 2);
                    new_header_tmp += 2;
                }

                conn->new_header = new_header;
                conn->new_header_len = new_header_tmp - new_header;
            }
            LOGD("drain size = %d, len = %lu", drain_size, len);
            evbuffer_drain(bev_buffer, drain_size);

            // check need auth
            if (conn->auth_result == PROXY_AUTH_RESULT_NEED_AUTH)
            {
                LOGE("need auth");
                const char *response_data = "HTTP/1.1 407 Proxy Authentication Required\r\n" HTTP_HEADER_PROXY_AUTHENTICATE "Basic realm=\".\"\r\n\r\n";
                if (bufferevent_write(conn->bev, response_data, strlen(response_data)) == -1)
                {
                    LOGE("write response message failed: errno = %d", errno);
                    free_http_proxy_conn(conn);
                    free_http_proxy_conn(conn->partner);
                    return;
                }
                return;
            }

            // connect to remote
            LOGD("connect to remote server");
            if (conn->partner == NULL || conn->partner->status != HTTP_PROXY_STATUS_OK || strcmp(conn->remote_host, conn->partner->host))
            {
                free_http_proxy_conn(conn->partner);
                struct bufferevent *partner = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
                if (partner == NULL)
                {
                    LOGE("bufferevent_socket_new failed");
                    free_http_proxy_conn(conn);
                    return;
                }

                char *s = strstr(conn->remote_host, ":");
                int port = 0;
                if (s == NULL)
                {
                    LOGE("parse remote host (%s) failed: ", conn->remote_host);
                    free(conn->remote_host);
                    free_http_proxy_conn(conn);
                    return;
                }

                int s_len = strlen(conn->remote_host) - strlen(s);
                char host[s_len + 1];
                host[s_len] = '\0';
                memcpy(host, conn->remote_host, s_len);

                port = atoi(s + 1);

                LOGD("connect to %s:%d", host, port);
                if (bufferevent_socket_connect_hostname(partner, NULL, AF_UNSPEC, host, port) == -1)
                {
                    free(conn->remote_host);
                    free(host);
                    LOGE("connect failed");
                    free_http_proxy_conn(conn);
                    return;
                }

                struct http_proxy_conn *partner_conn = (struct http_proxy_conn *)malloc(sizeof(struct http_proxy_conn));
                bzero(partner_conn, sizeof(struct http_proxy_conn));
                partner_conn->type = TYPE_REMOTE;
                partner_conn->partner = conn;
                partner_conn->partner->status = HTTP_PROXY_STATUS_RESPONSE;
                partner_conn->bev = partner;
                partner_conn->rfc = conn->rfc;
                partner_conn->host = conn->remote_host;

                conn->partner = partner_conn;
                conn->remote_host = NULL;

                bufferevent_setcb(partner, socks_read_cb, socks_write_cb, event_cb, partner_conn);
                bufferevent_enable(partner, EV_READ | EV_WRITE);
                bufferevent_set_timeouts(partner, &connect_timeout, &connect_timeout);
            }
            else if (conn->partner != NULL && conn->partner->status == HTTP_PROXY_STATUS_OK)
            {
                LOGI("reuse conn and write data to remote: input length = %zu, output length = %zu", evbuffer_get_length(bufferevent_get_input(conn->bev)), evbuffer_get_length(bufferevent_get_output(conn->bev)));
                write_data_to_remote(conn->partner);
            }
            else
            {
                LOGE("bad connection");
                PRINT_HTTP_PROXY_CONN(conn);
                PRINT_HTTP_PROXY_CONN(conn->partner);
            }
        }
    }
    else if (conn->status == HTTP_PROXY_STATUS_OK && conn->partner != NULL && conn->partner->status == HTTP_PROXY_STATUS_OK)
    {
        LOGD("copy data from %s -> %s", conn_type(conn->type), conn_type(conn->partner->type));
        struct evbuffer *src = bufferevent_get_input(conn->bev);
        struct evbuffer *dest = bufferevent_get_output(conn->partner->bev);

        size_t src_len = evbuffer_get_length(src);
        char *data = NULL;
        size_t data_len = 0;
        if (conn->type == TYPE_CLIENT && RFC_7230 == conn->rfc)
        {
            if (conn->write_body_length + src_len > conn->content_length)
            {
                data_len = conn->content_length - conn->write_body_length;
                data = (char *)malloc(data_len);
                if (evbuffer_remove(src, data, data_len) == -1)
                {
                    free(data);
                    data = NULL;
                    LOGD("read data failed");
                    return;
                }
                conn->status = HTTP_PROXY_STATUS_REQUEST;
            }
            else if (conn->write_body_length + src_len == conn->content_length)
            {
                conn->status = HTTP_PROXY_STATUS_REQUEST;
            }

            if (conn->status == HTTP_PROXY_STATUS_REQUEST)
            {
                LOGI("fd = %d reuse socket", bufferevent_getfd(conn->bev));
            }
        }
        LOGD("src len = %zu", src_len);
        if (data != NULL)
        {
            bufferevent_write(conn->partner->bev, data, data_len);
            free(data);
            data = NULL;
        }
        else
        {
            evbuffer_add_buffer(dest, src);
        }

        if (evbuffer_get_length(dest) > MAX_OUTPUT)
        {
            LOGD("bufferevent_setwatermark");
            bufferevent_setcb(conn->partner->bev, socks_read_cb, drained_writecb, event_cb, conn->partner);
            bufferevent_setwatermark(conn->partner->bev, EV_WRITE, MAX_OUTPUT / 2, MAX_OUTPUT);
            bufferevent_disable(conn->bev, EV_READ);
        }
    }
    else if (conn->type == TYPE_REMOTE && conn->status == HTTP_PROXY_STATUS_OK && conn->partner != NULL)
    {
        LOGD("copy remote data to client");
        struct evbuffer *src = bufferevent_get_input(conn->bev);
        struct evbuffer *dest = bufferevent_get_output(conn->partner->bev);

        evbuffer_add_buffer(dest, src);

        if (evbuffer_get_length(dest) > MAX_OUTPUT)
        {
            LOGD("bufferevent_setwatermark");
            bufferevent_setcb(conn->partner->bev, socks_read_cb, drained_writecb, event_cb, conn->partner);
            bufferevent_setwatermark(conn->partner->bev, EV_WRITE, MAX_OUTPUT / 2, MAX_OUTPUT);
            bufferevent_disable(conn->bev, EV_READ);
        }
    }
    else if (conn->type == TYPE_REMOTE && conn->partner == NULL)
    {
        free_http_proxy_conn(conn);
    }
    else
    {
        LOGE("未知错误: conn");
        PRINT_HTTP_PROXY_CONN(conn);
        LOGE("parter");
        PRINT_HTTP_PROXY_CONN(conn->partner);
    }
}

static void write_data_to_remote(struct http_proxy_conn *conn)
{
    int fd = bufferevent_getfd(conn->bev);
    if (fd == -1)
    {
        return;
    }
    struct sockaddr addr;
    socklen_t s_len;
    if (getpeername(fd, &addr, &s_len) == -1)
        return;

    struct http_proxy_conn *client_conn = conn->partner;
    LOGD("frc = %s; fd = %d, addr = %s, bev = %p", conn->rfc, fd, sockaddr_to_string(&addr, NULL, 0), conn->bev);
    if (strcmp(conn->rfc, RFC_7231) == 0)
    {
        LOGD("send success message to client");
        PRINT_HTTP_PROXY_CONN(client_conn);

        if (bufferevent_write(client_conn->bev, RFC_7231_OK_RESPONSE, strlen(RFC_7231_OK_RESPONSE)) == -1)
        {
            LOGE("write response message failed: errno = %d", errno);
            free_http_proxy_conn(conn);
            free_http_proxy_conn(client_conn);
            return;
        }
        client_conn->status = HTTP_PROXY_STATUS_OK;
    }
    else if (strcmp(conn->rfc, RFC_7230) == 0)
    {
        if (client_conn->new_header == NULL)
        {
            LOGE("new header is NULL: errno = %d", errno);
            free_http_proxy_conn(conn);
            free_http_proxy_conn(client_conn);
            return;
        }
        LOGD("new header (%lu:%d): \r\n%s", strlen(client_conn->new_header), client_conn->new_header_len, client_conn->new_header);
        if (bufferevent_write(conn->bev, client_conn->new_header, client_conn->new_header_len) == -1)
        {
            LOGE("write response message failed: errno = %d", errno);
            free_http_proxy_conn(conn);
            free_http_proxy_conn(client_conn);
            return;
        }
        free(client_conn->new_header);
        client_conn->new_header = NULL;

        if (client_conn->content_length == HTTP_REQUEST_DEFAULT_LENGTH)
        {
            // reset client status
            client_conn->status = HTTP_PROXY_STATUS_REQUEST;
        }
        else
        {
            client_conn->status = HTTP_PROXY_STATUS_OK;
        }
    }
    else
    {
        LOGE("bad rfc = %s", conn->rfc);
    }
    conn->status = HTTP_PROXY_STATUS_OK;
}

static void event_cb(struct bufferevent *bev, short what, void *ctx)
{
    LOGD("");
    struct http_proxy_conn *conn = (struct http_proxy_conn *)ctx;
    LOGD("type = %s; what = %d", conn_type(conn->type), what);
    if (what & (BEV_EVENT_READING | BEV_EVENT_WRITING | BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT))
    {
        if (conn->partner == NULL)
        {
            free_http_proxy_conn(conn);
            return;
        }
        struct evbuffer *src = bufferevent_get_output(conn->partner->bev);
        if (src != NULL)
        {
            if (evbuffer_get_length(src) != 0)
            {
                conn->partner->status = HTTP_PROXY_STATUS_FINISHING;
                conn->partner->partner = NULL;
            }
            else
            {
                free_http_proxy_conn(conn->partner);
            }
        }
        else
        {
            free_http_proxy_conn(conn->partner);
        }
        free_http_proxy_conn(conn);
    }
    else if (what & BEV_EVENT_CONNECTED)
    {
        if (conn->type == TYPE_REMOTE)
        {
            write_data_to_remote(conn);
        }
    }
}

static void socks_write_cb(struct bufferevent *bev, void *ctx)
{
    struct http_proxy_conn *conn = (struct http_proxy_conn *)ctx;
    struct evbuffer *src = bufferevent_get_output(bev);
    LOGD("src type = %s; output size = %zu", conn_type(conn->type), evbuffer_get_length(src));

    if (conn->type == TYPE_CLIENT && conn->auth_result == PROXY_AUTH_RESULT_NEED_AUTH)
    {
        LOGI("send proxy auth to client");
        if (evbuffer_get_length(src) == 0)
        {
            conn->status = HTTP_PROXY_STATUS_REQUEST;
            return;
        }
    }

    if (conn->status == HTTP_PROXY_STATUS_FINISHING)
    {
        if (evbuffer_get_length(src) == 0)
        {
            struct sockaddr addr;
            socklen_t s_len;
            if (getpeername(bufferevent_getfd(bev), &addr, &s_len) == -1)
                return;
            LOGI("close %s; address = %s", conn_type(conn->type), sockaddr_to_string(&addr, NULL, 0));
            free_http_proxy_conn(conn);
        }
    }
}

static void connect_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *ctx)
{
    LOGD("");
    LOGD("new connect: fd = %d; address = %s", fd, sockaddr_to_string(addr, NULL, 0));
    struct http_proxy_conn *conn = NULL;
    if (ctx == NULL)
    {
        conn = (struct http_proxy_conn *)malloc(sizeof(struct http_proxy_conn));
        bzero(conn, sizeof(struct http_proxy_conn));

        conn->type = TYPE_CLIENT;
        conn->status = HTTP_PROXY_STATUS_REQUEST;
#ifdef USE_OPENSSL
        if (use_ssl)
        {
            SSL *ssl = SSL_new(ssl_ctx);
            conn->bev = bufferevent_openssl_socket_new(base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
        }
        else
            conn->bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
#else
        conn->bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
#endif
    }

    struct clib_addr ca;
    if (parse_clib_addr(addr, &ca) != 0)
    {
        LOGE("parse addr failed: errno = %d; %s", errno, strerror(errno));
        return;
    }

    conn->host = strdup(sockaddr_to_string(addr, NULL, 0));

    bufferevent_setcb(conn->bev, socks_read_cb, socks_write_cb, event_cb, conn);
    bufferevent_enable(conn->bev, EV_READ | EV_WRITE);
}

static void signal_cb(evutil_socket_t fd, short event, void *arg)
{
    LOGD("fd = %d", fd);
    exit(0);
}

void set_ssl(const char *key_path, const char *cert_path)
{
    use_ssl = key_path != NULL && cert_path != NULL;
    if (use_ssl)
        ssl_ctx = proxy_init_ssl(key_path, cert_path);
    use_ssl = use_ssl && ssl_ctx != NULL;
}

static void auth_info_free_cb(void *v)
{
    if (v == NULL)
        return;

    ProxyAuthInfo *info = (ProxyAuthInfo *)v;

    free(info->username);
    free(info->password);

    free(info);
}

void add_proxy_auth_info(const char *username, const char *password)
{
    LOGI("add auth info: username = %s, password = %s", username, password);
    if (username == NULL || password == NULL)
    {
        return;
    }

    if (auth_info_map == NULL)
    {
        auth_info_map = (CHashMap *)malloc(sizeof(CHashMap));
        bzero(auth_info_map, sizeof(CHashMap));
        c_hash_map_init(auth_info_map);
        auth_info_map->free_cb = auth_info_free_cb;
    }

    ProxyAuthInfo *info = (ProxyAuthInfo *)malloc(sizeof(ProxyAuthInfo));
    info->username = strdup(username);
    info->password = strdup(password);

    c_hash_map_put(auth_info_map, (char *)username, (void *)info);
}

int start_http_server(const char *ip, int port)
{
    LOGI("socks5 server ip = %s; port = %d", ip, port);
    if (ip == NULL || strlen(ip) == 0)
    {
        return -1;
    }

    int ipv6 = 0;
    size_t i;
    for (i = 0; i < strlen(ip); i++)
    {
        if (ip[i] == ':')
        {
            ipv6 = 1;
            break;
        }
    }

    char addr_str[strlen(ip) + 7];
    bzero(addr_str, sizeof(addr_str));
    if (ipv6)
    {
        sprintf(addr_str, "[%s]:%d", ip, port);
    }
    else
    {
        sprintf(addr_str, "%s:%d", ip, port);
    }

    struct sockaddr_storage addr;

    int addr_len = sizeof(addr);
    if (evutil_parse_sockaddr_port(addr_str, (struct sockaddr *)&addr, &addr_len))
    {
        LOGE("parse sockaddr failed");
        return -1;
    }

    base = event_base_new();
    if (base == NULL)
    {
        LOGE("event_base_new: failed, errno = %d; %s", errno, strerror(errno));
        return -1;
    }

    dns_base = evdns_base_new(base, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
    evdns_base_nameserver_ip_add(dns_base, "1.1.1.1");

    listener = evconnlistener_new_bind(base, connect_cb, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE, -1, (struct sockaddr *)&addr, addr_len);

    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);
    return 0;
}