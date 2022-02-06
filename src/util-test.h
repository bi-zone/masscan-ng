#include <stdio.h>

#include "logger.h"
#include "util-cross.h"

#define GET_MACRO_REGRESS(_1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME
#define REGRESS_1(x)                                                           \
  if (!(x)) {                                                                  \
    return (                                                                   \
        LOG(LEVEL_ERROR, "Regression failed %s:%d.\n", __FILE__, __LINE__) |   \
        1);                                                                    \
  }
#define REGRESS_2(x, str_fmt)                                                  \
  if (!(x)) {                                                                  \
    return (LOG(LEVEL_ERROR, "Regression failed %s:%d. " str_fmt "\n",         \
                __FILE__, __LINE__) |                                          \
            1);                                                                \
  }
#define REGRESS_3(x, str_fmt, ...)                                             \
  if (!(x)) {                                                                  \
    return (LOG(LEVEL_ERROR, "Regression failed %s:%d. " str_fmt "\n",         \
                __FILE__, __LINE__, __VA_ARGS__) |                             \
            1);                                                                \
  }
#define REGRESS_NOT_RET_1(x)                                                   \
  if (!(x)) {                                                                  \
    LOG(LEVEL_ERROR, "Regression failed %s:%d.\n", __FILE__, __LINE__);        \
  }
#define REGRESS_NOT_RET_2(x, str_fmt)                                          \
  if (!(x)) {                                                                  \
    LOG(LEVEL_ERROR, "Regression failed %s:%d. " str_fmt "\n", __FILE__,       \
        __LINE__);                                                             \
  }
#define REGRESS_NOT_RET_3(x, str_fmt, ...)                                     \
  if (!(x)) {                                                                  \
    LOG(LEVEL_ERROR, "Regression failed %s:%d. " str_fmt "\n", __FILE__,       \
        __LINE__, __VA_ARGS__);                                                \
  }
#define REGRESS(...)                                                           \
  GET_MACRO_REGRESS(__VA_ARGS__, REGRESS_3, REGRESS_3, REGRESS_3, REGRESS_3,   \
                    REGRESS_3, REGRESS_3, REGRESS_2, REGRESS_1)                \
  (__VA_ARGS__)
#define REGRESS_NOT_RET(...)                                                   \
  GET_MACRO_REGRESS(__VA_ARGS__, REGRESS_NOT_RET_3, REGRESS_NOT_RET_3,         \
                    REGRESS_NOT_RET_3, REGRESS_NOT_RET_3, REGRESS_NOT_RET_3,   \
                    REGRESS_NOT_RET_3, REGRESS_NOT_RET_2, REGRESS_NOT_RET_1)   \
  (__VA_ARGS__)
#define REGRESS_ERROR() REGRESS(false)
