#ifndef PROTO_HTTP_OVER_SSL_H
#define PROTO_HTTP_OVER_SSL_H
#include "proto-banner1.h"

extern struct ProtocolParserStream banner_http_over_ssl;
struct ProtocolParserStream *
get_ssl_parser_stream(const struct Banner1 *banner1);

#endif
