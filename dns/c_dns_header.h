#ifndef C_DNS_HEADER_H
#define C_DNS_HEADER_H

#define C_DNS_HEADER_LENGTH 12

#define C_DNS_FLAG_QUERY 0
#define C_DNS_FLAG_RESPONSE 1

// a standard query (QUERY)
#define C_DNS_OPCODE_QUERY 0
// an inverse query (IQUERY)
#define C_DNS_OPCODE_IQUERY 1
// a server status request (STATUS)
#define C_DNS_OPCODE_STATUS 2

// No error condition
#define C_DNS_FLAG_RESPONSE_NO_ERROR 0

// Format error - The name server was
// unable to interpret the query.
#define C_DNS_FLAG_RESPONSE_FORMAT_ERROR 1

// Server failure - The name server was
// unable to process this query due to a
// problem with the name server.
#define C_DNS_FLAG_RESPONSE_SERVER_FAILURE 2

// Name Error - Meaningful only for
// responses from an authoritative name
// server, this code signifies that the
// domain name referenced in the query does
// not exist.
#define C_DNS_FLAG_RESPONSE_NAME_ERROR 3

// Not Implemented - The name server does
// not support the requested kind of query.
#define C_DNS_FLAG_RESPONSE_NOT_IMPL 4

// Refused - The name server refuses to
// perform the specified operation for
// policy reasons.  For example, a name
// server may not wish to provide the
// information to the particular requester,
// or a name server may not wish to perform
// a particular operation (e.g., zone
// transfer) for particular data.
#define C_DNS_FLAG_RESPONSE_REFUSED 5

// get response error reason
const char *c_dns_flag_response_error_reason(unsigned char code);

// FLAGS
//
// QR - A one bit field that specifies whether this message is a
// query (0), or a response (1).

// A four bit field that specifies kind of query in this
// message.  This value is set by the originator of a query
// and copied into the response
// 0               a standard query (QUERY)
// 1               an inverse query (IQUERY)
// 2               a server status request (STATUS)
// 3-15            reserved for future use
//
//
// Authoritative Answer - this bit is valid in responses,
// and specifies that the responding name server is an
// authority for the domain name in question section.
//
// Note that the contents of the answer section may have
// multiple owner names because of aliases.  The AA bit
// corresponds to the name which matches the query name, or
// the first owner name in the answer section.
//
//
// TrunCation - specifies that this message was truncated
// due to length greater than that permitted on the
// transmission channel.
//
//
// Recursion Desired - this bit may be set in a query and
// is copied into the response.  If RD is set, it directs
// the name server to pursue the query recursively.
// Recursive query support is optional.
//
//
// Recursion Available - this be is set or cleared in a
// response, and denotes whether recursive query support is
// available in the name server.
//
//
// Reserved for future use.  Must be zero in all queries
// and responses.
//
//
// Response code - this 4 bit field is set as part of
// responses.  The values have the following
// interpretation:
// 0               No error condition
// 1               Format error - The name server was
//                 unable to interpret the query.
//
// 2               Server failure - The name server was
//                 unable to process this query due to a
//                 problem with the name server.
//
// 3               Name Error - Meaningful only for
//                 responses from an authoritative name
//                 server, this code signifies that the
//                 domain name referenced in the query does
//                 not exist.
//
// 4               Not Implemented - The name server does
//                 not support the requested kind of query.
//
// 5               Refused - The name server refuses to
//                 perform the specified operation for
//                 policy reasons.  For example, a name
//                 server may not wish to provide the
//                 information to the particular requester,
//                 or a name server may not wish to perform
//                 a particular operation (e.g., zone
//
typedef struct c_dns_header
{
    unsigned short transaction_id;

    unsigned char rd : 1;     // recursion desired
    unsigned char tc : 1;     // truncated message
    unsigned char aa : 1;     // authoritive answer
    unsigned char opcode : 4; // purpose of message
    unsigned char qr : 1;     // query/response flag

    unsigned char rcode : 4; // response code
    unsigned char cd : 1;    // checking disabled
    unsigned char ad : 1;    // authenticated data
    unsigned char z : 1;     // its z! reserved
    unsigned char ra : 1;    // recursion available

    unsigned short questions;
    unsigned short answer_count;
    unsigned short authority_count;
    unsigned short additional_count;
} DNSHeader;

#endif