/*
    log messages to console, depending on verbose level

    Use -d to get more verbose output. The more -v you add, the
    more verbose the output becomes.

    Details about the running of the program go to <stderr>.
    Details about scan results go to <stdout>, so that they can easily
    be redirected to a file.
*/
#include "logger.h"
#include "string_s.h"
#include "util-cross.h"

#include <stdarg.h>

#include <openssl/err.h>

static int global_debug_level = LEVEL_WARNING; /* yea! a global variable!! */
void LOG_add_level(int x) { global_debug_level += x; }

/***************************************************************************
 ***************************************************************************/
int vLOG(int level, const char *fmt, va_list marker) {
  int res = 0;
  if (level <= global_debug_level) {
    res = vfprintf(stderr, fmt, marker);
    fflush(stderr);
  }
  return res;
}

/***************************************************************************
 * Prints the message if the global "verbosity" flag exceeds this level.
 ***************************************************************************/
int LOG(int level, const char *fmt, ...) {
  int res = 0;
  va_list marker;

  va_start(marker, fmt);
  res = vLOG(level, fmt, marker);
  va_end(marker);
  return res;
}

/***************************************************************************
 ***************************************************************************/
static int vLOGip(int level, const ipaddress *ip, unsigned port,
                  const char *fmt, va_list marker) {
  int res = 0;
  if (level <= global_debug_level) {
    char sz_ip[64];
    ipaddress_formatted_t fmt1;
    ipaddress_fmt(&fmt1, ip);

    sprintf_s(sz_ip, sizeof(sz_ip), "%s", fmt1.string);
    fprintf(stderr, "%-15s:%5u: ", sz_ip, port);
    res = vfprintf(stderr, fmt, marker);
    fflush(stderr);
  }
  return res;
}

/***************************************************************************
 ***************************************************************************/
int LOGip(int level, const ipaddress *ip, unsigned port, const char *fmt, ...) {
  int res = 0;
  va_list marker;

  va_start(marker, fmt);
  res = vLOGip(level, ip, port, fmt, marker);
  va_end(marker);
  return res;
}

/***************************************************************************
 ***************************************************************************/
static int LOGopenssl_cb(const char *str, size_t len, void *bp) {
  UNUSEDPARM(bp);

  if (len > INT16_MAX) {
    return -1;
  }
  fprintf(stderr, "%.*s", (int)len, str);
  return 1;
}

int LOGopenssl(int level) {
  int res = 0;
  if (level <= global_debug_level) {
    fprintf(stderr, "OpenSSL error:\n");
    ERR_print_errors_cb(LOGopenssl_cb, NULL);
    fprintf(stderr, "\n");
    fflush(stderr);
  }
  return res;
}