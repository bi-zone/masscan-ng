#ifndef LOGGER_H
#define LOGGER_H
#include "massip-addr.h"

#include <stdarg.h>

#define LEVEL_ERROR 0
#define LEVEL_WARNING 1
#define LEVEL_INFO 2
#define LEVEL_DEBUG 3
#define LEVEL_DEBUG_1 4
#define LEVEL_DEBUG_2 5
#define LEVEL_DEBUG_3 6
#define LEVEL_DEBUG_4 7
#define LEVEL_DEBUG_5 8

int LOG(int level, const char *fmt, ...);
int vLOG(int level, const char *fmt, va_list marker);
int LOGip(int level, const ipaddress *ip, unsigned port, const char *fmt, ...);
int LOGopenssl(int level);

void LOG_add_level(int level);

#endif
