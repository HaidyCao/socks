#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>

#include "c_dns.h"
#include "c_dns_header.h"
#include "../log.h"
#include "../lib/c_hex_utils.h"

#define C_DNS_NAME_PTR_LEN 2

static char *domain_to_dns_name_format(char *domain) {
    char *dns = malloc(strlen(domain) + 2);

    int p_index = 0;
    int num = 0;
    size_t i;
    for (i = 0; i < strlen(domain); i++) {
        if (domain[i] == '.') {
            dns[p_index] = num;
            p_index = i + 1;
            num = 0;
        } else {
            dns[i + 1] = domain[i];
            num++;
        }
    }
    dns[p_index] = num;
    dns[strlen(domain) + 1] = '\0';
    return dns;
}

static int get_name(char *data, size_t data_len, char *name_start, char **result, size_t *offset) {
    char *name = NULL;
    char *start = name_start;
    int name_size = 0;
    if (offset != NULL)
        *offset = start - data;
    while (1) {
        if (start[0] == '\0') {
            LOGD("find to end");
            name_size++;
            break;
        }

        int is_ptr = ((u_char) (start[0]) >> 6) == 0x03;
        if (is_ptr) {
            LOGD("find by ptr");
            name_size += 2;
            typedef struct {
                u_char v_h;
                u_char v_l;
            } DNS_ushort;
            DNS_ushort *us = (DNS_ushort *) start;
            u_short r_offset = (((u_short) (us->v_h & 0x03)) << 4) + us->v_l;
            LOGD("vh = %d, vl = %d, r_offset = %d", us->v_h, us->v_l, r_offset);
            if (r_offset > data_len) {
                free(name);
                return -1;
            }

            size_t *i_offset = NULL;
            char *left_name = NULL;
            get_name(data, data_len, data + r_offset, &left_name, name == NULL ? offset : i_offset);
            if (name == NULL)
                name = left_name;
            else {
                char *new_name = NULL;
                asprintf(&new_name, "%s.%s", name, left_name);
                free(name);
                free(left_name);
                name = new_name;
            }
            break;
        } else {
            name_size += start[0] + 1;
            if (name == NULL)
                name = strndup(start + 1, start[0]);
            else {
                char *new_name = NULL;
                char *tmp = strndup(start + 1, start[0]);
                asprintf(&new_name, "%s.%s", name, tmp);
                free(tmp);
                free(name);
                name = new_name;
            }

            start += start[0] + 1;
        }
    }
    *result = name;
    return name_size;
}

typedef struct {
    u_short type;
    u_short class;
} QuestionBase;

typedef struct {
    char *name;
    QuestionBase *base;
} DNSQuestion;

#pragma pack(push, 1)
typedef struct {
    u_short type;
    u_short class;
    uint ttl;
    u_short data_length;
} RDATA_Header;
#pragma pack(pop)

#define SIZEOF_RDATA_WITHOUT_DATA (sizeof(RDATA) - sizeof(char *))

typedef struct c_dns_resource {
    char *name;
    RDATA_Header header;
    char *data;
} DNSResource;
typedef DNSResource DNSAnswer;

ssize_t c_dns_pack(char *domain, char *buf, size_t buf_len, u_short type) {
    if (buf_len < sizeof(DNSHeader)) {
        LOGD("buf is to short");
        return -1;
    }
    DNSHeader *header = (DNSHeader *) buf;
    header->transaction_id = (unsigned short) htons(getpid());
    header->qr = C_DNS_FLAG_QUERY;
    header->opcode = C_DNS_OPCODE_QUERY;
    header->aa = 0;
    header->tc = 0;
    header->rd = 1;
    header->ra = 0;
    header->z = 0;
    header->rcode = 0;
    header->questions = htons(1);
    header->answer_count = 0;
    header->authority_count = 0;
    header->additional_count = 0;

    char *dns_fmt_name = domain_to_dns_name_format(domain);
    memcpy(buf + sizeof(DNSHeader), dns_fmt_name, strlen(dns_fmt_name) + 1);
    QuestionBase *base = (QuestionBase *) (buf + sizeof(DNSHeader) + strlen(dns_fmt_name) + 1);
    base->type = htons(type);
    base->class = htons(C_DNS_CLASS_IN);

    return sizeof(DNSHeader) + strlen(dns_fmt_name) + 1 + sizeof(QuestionBase);
}

void c_dns_free_hostent(struct hostent *host) {
    free(host->h_name);

    int i = 0;
    char *v;
    while ((v = host->h_aliases[i]) != NULL) {
        free(v);
        i++;
    }
    free(host->h_aliases);

    i = 0;

    while ((v = host->h_addr_list[i]) != NULL) {
        free(v);
        i++;
    }
    free(host->h_addr_list);
    free(host);
}

int c_dns_parse_a(char *data, unsigned int len, struct hostent **host) {
//    hexDump(data, len, 0);
    DNSHeader *header = (DNSHeader *) data;
    if (header->qr != C_DNS_FLAG_RESPONSE) {
        LOGD("not response data");
        return -1;
    }

    if (header->rcode != C_DNS_FLAG_RESPONSE_NO_ERROR) {
        LOGD("parse failed: response code = %d, reason = %s, answer count = %d", header->rcode,
             c_dns_flag_response_error_reason(header->rcode), ntohs(header->answer_count));
        return -1;
    }

    u_short question_count = ntohs(header->questions);
    size_t q_size = 0;

    for (size_t i = 0; i < question_count; i++) {
        DNSQuestion question;
        int name_size = get_name(data, len, data + C_DNS_HEADER_LENGTH + q_size, &question.name, NULL);
        if (name_size == -1) {
            LOGI("parse question failed");
            return -1;
        }
        LOGD("q name = %s; name size = %d", question.name, name_size);
        free(question.name);
        q_size += name_size + sizeof(QuestionBase);
        LOGD("q_size = %zu", q_size);
    }

    u_short answer_count = ntohs(header->answer_count);
    LOGD("answer count = %d", answer_count);
    if (answer_count <= 0) {
        LOGD("parse failed: no answer");
        return -1;
    }

    struct hostent *h = calloc(1, sizeof(struct hostent));
    h->h_addrtype = AF_INET;
    h->h_length = 4;
    h->h_aliases = calloc(header->answer_count + 1, sizeof(char *));
    h->h_addr_list = calloc(header->answer_count + 1, sizeof(char *));

    int answer_len = 0;
    int a_answer_count = 0;
    int a_aliases_count = 0;
    size_t i;
    for (i = 0; i < answer_count; i++) {
        char *start = data + C_DNS_HEADER_LENGTH + q_size + answer_len;
        hexDump(start, 2, 0);
        DNSAnswer answer;
        int name_size = 0;
        name_size = get_name(data, len, start, &answer.name, NULL);
        if (name_size == -1) {
            c_dns_free_hostent(h);
            LOGI("get name faild");
            return -1;
        }
        answer.header = *(RDATA_Header *) (start + name_size);

        LOGD("answer name = %s, name_size = %d, type = %d, class = %d", answer.name, name_size,
             ntohs(answer.header.type), ntohs(answer.header.class));

        if (h->h_name == NULL) {
            LOGD("answer name = %s", answer.name);
            h->h_name = answer.name;
        }

        u_short data_len = ntohs(answer.header.data_length);
        LOGD("data len = %d, RDATA_Header len = %zu", data_len, sizeof(RDATA_Header));
        if (ntohs(answer.header.type) != C_DNS_QTYPE_A || ntohs(answer.header.class) != C_DNS_CLASS_IN) {
            if (ntohs(answer.header.type) != C_DNS_QTYPE_CNAME || ntohs(answer.header.class) != C_DNS_CLASS_IN) {
                int r = get_name(data, len, start + name_size + sizeof(RDATA_Header), &h->h_aliases[a_aliases_count],
                                 NULL);
                if (r == -1) {
                    c_dns_free_hostent(h);
                    return -1;
                }
                LOGD("alia = %s", h->h_aliases[a_aliases_count]);
                a_aliases_count++;
            }
            hexDump(start + name_size + sizeof(RDATA_Header), data_len, 0);
            answer_len += name_size + sizeof(RDATA_Header) + data_len;
            continue;
        }
        hexDump(start + name_size, sizeof(RDATA_Header), 0);

        LOGD("TTL = %u; data len = %d", ntohl(answer.header.ttl), data_len);

        char *rdata = malloc(data_len);
        memcpy(rdata, start + name_size + sizeof(RDATA_Header), data_len);
        h->h_addr_list[a_answer_count] = rdata;
        a_answer_count++;

        answer_len += name_size + sizeof(RDATA_Header) + data_len;
    }
    *host = h;

    return 0;
}

#define FREE_DOMAINS(domains, count) \
    int k = 0;                       \
    for (; k < count; k++)           \
    {                                \
        free(domains[k].domain);     \
        domains[k].domain = NULL;    \
    }

int c_dns_gen_inet_response(char *data, size_t len, char **resp_data, size_t *resp_len, c_dns_ipv4_cb ipv4_cb,
                            c_dns_ipv6_cb ipv6_cb) {
    if (data == NULL || len < sizeof(DNSHeader)) {
        LOGD("data is null or to short");
        return -1;
    }

    hexDump(data, len, 0);

    DNSHeader *header = (DNSHeader *) data;
    if (header->qr != C_DNS_FLAG_QUERY) {
        LOGD("not query data");
        return -1;
    }

    int q_count = ntohs(header->questions);
    if (q_count == 0) {
        LOGD("not questions");
        return -1;
    }
    typedef struct {
        char *domain;
        u_short offset;
        u_short type;
    } DomainOffset;

    DomainOffset domains[q_count];
    int domain_count = 0;

    size_t resp_data_len = len;

    size_t q_size = 0;
    size_t i;
    for (i = 0; i < q_count; i++) {
        char *start = data + sizeof(DNSHeader) + q_size;
        if (start > data + len) {
            FREE_DOMAINS(domains, domain_count);
            LOGD("out of range");
            return -1;
        }
        char *name = NULL;
        size_t offset = 0;
        int name_size = get_name(data, len, start, &name, &offset);
        if (name_size == -1) {
            FREE_DOMAINS(domains, domain_count);
            LOGD("name size is -1");
            return -1;
        }
        LOGD("name size = %d", name_size);
        QuestionBase *base = (QuestionBase *) (start + name_size);
        int type = ntohs(base->type);
        if (ntohs(base->class) != C_DNS_CLASS_IN || (type != C_DNS_QTYPE_A && type != C_DNS_QTYPE_AAAA)) {
            LOGD("class = %d, type = %d", ntohs(base->class), type);
            q_size += name_size + sizeof(QuestionBase);
            continue;
        }

        domains[domain_count].domain = name;
        domains[domain_count].offset = offset;
        domains[domain_count].type = base->type;
        domain_count++;

        q_size += name_size + sizeof(QuestionBase);
        resp_data_len += C_DNS_NAME_PTR_LEN + sizeof(RDATA_Header) +
                         (type == C_DNS_QTYPE_A ? sizeof(struct in_addr) : sizeof(struct in6_addr));
    }

    // create response
    char *rdata = malloc(resp_data_len);
    memcpy(rdata, data, len);
    DNSHeader *rheader = (DNSHeader *) rdata;
    rheader->qr = C_DNS_FLAG_RESPONSE;
    rheader->answer_count = htons(domain_count);

    size_t a_size = 0;
    for (i = 0; i < domain_count; i++) {
        DomainOffset *d = &domains[i];
        char *start = rdata + sizeof(DNSHeader) + q_size + a_size;
        LOGD("offset = %d", d->offset);
        typedef struct {
            u_short offset;
        } I_OFFSET;

        I_OFFSET *io = (I_OFFSET *) start;
        io->offset = 0xC0 | htons(d->offset);

        RDATA_Header *h = (RDATA_Header *) (start + C_DNS_NAME_PTR_LEN);
        h->type = htons(C_DNS_QTYPE_A);
        h->class = htons(C_DNS_CLASS_IN);
        h->ttl = htonl(0);

        struct in_addr *res_data = (struct in_addr *) (start + C_DNS_NAME_PTR_LEN + sizeof(RDATA_Header));
        if (ntohs(d->type) == C_DNS_QTYPE_A) {
            struct in_addr ip;
            int dl = sizeof(ip);
            h->data_length = htons(dl);
            if (ipv4_cb(d->domain, &ip) == -1) {
                FREE_DOMAINS(domains, domain_count);
                free(rdata);
                LOGD("get ipv4 failed");
                return -1;
            }
            memcpy(res_data, &ip, dl);
            a_size += C_DNS_NAME_PTR_LEN + sizeof(RDATA_Header) + dl;
        } else {
            struct in6_addr ip;
            int dl = sizeof(ip);
            h->data_length = htons(dl);
            if (ipv6_cb(d->domain, &ip) == -1) {
                FREE_DOMAINS(domains, domain_count);
                free(rdata);
                return -1;
            }
            memcpy(res_data, &ip, dl);
            a_size += C_DNS_NAME_PTR_LEN + sizeof(RDATA_Header) + dl;
        }
    }
    FREE_DOMAINS(domains, domain_count);

    *resp_data = rdata;
    *resp_len = resp_data_len;

    return 0;
}

int c_dns_parse_first_ip(struct hostent *host, struct sockaddr *addr, size_t *addr_len, int port) {
    if (host == NULL || addr == NULL) {
        return -1;
    }

    if (host->h_addr_list[0] != NULL) {
        if (host->h_addrtype == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *) addr;
            in->sin_family = AF_INET;
            in->sin_addr = *(struct in_addr *) host->h_addr_list[0];
            in->sin_port = ntohs(port);
            *addr_len = sizeof(struct sockaddr_in);
            return 0;
        } else if (host->h_addrtype == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) addr;
            in6->sin6_family = AF_INET6;

            in6->sin6_addr = *(struct in6_addr *) host->h_addr_list[0];
            in6->sin6_port = ntohs(port);
            *addr_len = sizeof(struct sockaddr_in6);
            return 0;
        }
    }
    return -1;
}
