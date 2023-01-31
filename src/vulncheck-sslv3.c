#include "proto-ssl.h"

#define TLS_FALLBACK_SCSV 0x5600
#define inappropriate_fallback 86

static char sslv3_hello[] =
    "\x16\x03\x00\x00\x43"
    "\x01\x00\x00\x3f\x03\x00"
    "\x00\x07\x06\x30" /* gmtime */
    "\x16"
    "\x79\xa4\xc3\xf0\xa9\xbe\x26\xf5\x1c\x36\xad\xff\x65\x0b\x9e\x2a"
    "\x8e\xef\x58\x1c\x16\x44\x12\x35\x93\x36\xb9"
    "\x00"     /* session id length = 0 */
    "\x00\x18" /* cipher suites length = 24 */
    "\x00\x39"
    "\x00\x38\x00\x35\x00\x33\x00\x32\x00\x04\x00\x05\x00\x2f\x00\x16"
    "\x00\x13\xfe\xff\x00\x0a\x01\x00";

char *ssl_hello_sslv3_template = sslv3_hello;
