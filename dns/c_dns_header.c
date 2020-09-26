#include <arpa/inet.h>

#include "c_dns_header.h"

const char *c_dns_flag_response_error_reason(unsigned char code)
{
    if (code == C_DNS_FLAG_RESPONSE_NO_ERROR)
        return "No Error";
    else if (code == C_DNS_FLAG_RESPONSE_FORMAT_ERROR)
        return "Format error";
    else if (code == C_DNS_FLAG_RESPONSE_SERVER_FAILURE)
        return "Server failure";
    else if (code == C_DNS_FLAG_RESPONSE_NAME_ERROR)
        return "Name Error";
    else if (code == C_DNS_FLAG_RESPONSE_NOT_IMPL)
        return "Not Implemented";
    else if (code == C_DNS_FLAG_RESPONSE_REFUSED)
        return "Refused";
    else
        return "Unknown Error";
}
