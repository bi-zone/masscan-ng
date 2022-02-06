/*
    safe "string" functions, like Microsoft's

    This is for the "safe" clib functions, where things like "strcpy()" is
    replaced with a safer version of the function, like "strcpy_s()". Since
    these things are non-standard, compilers deal with them differently.

 Reference:
 http://msdn.microsoft.com/en-us/library/bb288454.aspx
*/

#ifndef STRCPY_S
#define STRCPY_S

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_MSC_VER) && (_MSC_VER >= 1600)
/* > Visual Studio 2010*/
#include <direct.h>
#include <stdio.h>
#include <string.h>

#define strcasecmp _stricmp
#pragma warning(disable : 4996)
#define strncasecmp _strnicmp
#define memcasecmp _memicmp
#define getcwd _getcwd

#elif defined(_MSC_VER) && (_MSC_VER == 1200)
/* Visual Studio 6.0 */
#define sprintf_s _snprintf
#define strcasecmp _stricmp
#pragma warning(disable : 4996)
#define strncasecmp _strnicmp
#define memcasecmp _memicmp
#define vsprintf_s _vsnprintf
typedef int errno_t;
errno_t fopen_s(FILE **fp, const char *filename, const char *mode);

#elif defined(__GNUC__) && (__GNUC__ >= 4)
#include <unistd.h>
/* GCC 4 */
#define sprintf_s snprintf
#define vsprintf_s vsnprintf
int memcasecmp(const void *lhs, const void *rhs, int length);
typedef int errno_t;
#if !defined(WIN32) /* mingw */
errno_t fopen_s(FILE **fp, const char *filename, const char *mode);
errno_t strcpy_s(char *dst, size_t sizeof_dst, const char *src);
errno_t localtime_s(struct tm *_tm, const time_t *time);
errno_t gmtime_s(struct tm *_tm, const time_t *time);
#endif
#undef strerror

#else
#warning unknown compiler
#endif

#endif
