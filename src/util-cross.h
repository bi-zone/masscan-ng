#ifndef UTIL_CROSS_H
#define UTIL_CROSS_H

// inline
#if defined(_MSC_VER)
#define inline _inline
#endif

// bool
#if _MSC_VER && _MSC_VER < 1800
typedef enum { false = 0, true = 1 } bool;
#else
#include <stdbool.h>
#endif

// MAX MIN
#if defined(__GNUC__)
#define max(a, b)                                                              \
  ({                                                                           \
    typeof(a) _a = (a);                                                        \
    typeof(b) _b = (b);                                                        \
    _a > _b ? _a : _b;                                                         \
  })
#define min(a, b)                                                              \
  ({                                                                           \
    typeof(a) _a = (a);                                                        \
    typeof(b) _b = (b);                                                        \
    _a < _b ? _a : _b;                                                         \
  })
#endif

// ARRAY
#if defined(_MSC_VER)
#include <stdlib.h>
#define ARRAY_SIZE(arr) (_countof((arr)))
#elif defined(__GNUC__)
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int : -!!(e); }))
#define __must_be_array(a)                                                     \
  BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), typeof(&a[0])))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#else
#warning unknown compiler
#endif

// UNUSEDPARM
#ifndef UNUSEDPARM
#if defined(_MSC_VER)
#define UNUSEDPARM(x) x
#elif defined(__GNUC__)
#define UNUSEDPARM(x) (void)x
#endif
#endif

// TCP Flags
#ifndef TH_FIN
#define TH_FIN 0x01
#endif
#ifndef TH_SYN
#define TH_SYN 0x02
#endif
#ifndef TH_RST
#define TH_RST 0x04
#endif
#ifndef TH_PUSH
#define TH_PUSH 0x08
#endif
#ifndef TH_ACK
#define TH_ACK 0x10
#endif
#ifndef TH_URG
#define TH_URG 0x20
#endif
#ifndef TH_ECE
#define TH_ECE 0x40
#endif
#ifndef TH_CWR
#define TH_CWR 0x40
#endif

#define COUNT_TCP_PORTS 65536
#define COUNT_UDP_PORTS 65536
#define COUNT_SCTP_PORTS 65536
#define COUNT_OPROTO_PORTS 256
#define COUNT_ICMP_TYPES 256

#endif // UTIL_CROSS_H
