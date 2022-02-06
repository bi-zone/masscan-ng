#include "proto-signout.h"
#include "masscan-status.h"
#include "util-cross.h"
#include "util-malloc.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void signout_init(struct SignOutput *signout) {
  memset(signout, 0, sizeof(*signout));
  signout->is_empty = true;
}

void signout_release(struct SignOutput *signout) {
  while (signout->next) {
    struct SignOutput *next = signout->next->next;
    free(signout->next);
    signout->next = next;
  }
  signout_init(signout);
}

struct SignOutput *signout_new_sign(struct SignOutput *signout,
                                    time_t timestamp,
                                    enum ApplicationProtocol app_proto) {

  struct SignOutput *p;

  if (signout->is_empty) {
    signout->is_empty = false;
    signout->timestamp = timestamp;
    signout->app_proto = app_proto;
    return signout;
  }

  p = CALLOC(1, sizeof(*p));
  p->timestamp = timestamp;
  p->app_proto = app_proto;
  p->next = signout->next;
  signout->next = p;
  return p;
}

static size_t signout_count(const struct SignOutput *signout) {
  size_t count = 0;
  while (signout && signout->is_empty == false) {
    count += 1;
    signout = signout->next;
  }

  return count;
}

int signout_selftest(void) {
  /*
   * Basic test
   */
  {
    struct SignOutput signout[1];
    unsigned i;

    signout_init(signout);
    if (signout_count(signout) != 0) {
      return 1;
    }

    for (i = 0; i < 10; i++) {
      signout_new_sign(signout, time(0), PROTO_FTP);
      signout_new_sign(signout, time(0), PROTO_HTTPS);
    }
    if (signout->next == NULL) {
      return 1;
    }
    if (signout_count(signout) != 20) {
      return 1;
    }

    signout_release(signout);
    if (signout->next != NULL) {
      return 1;
    }
    if (signout_count(signout) != 0) {
      return 1;
    }
  }

  return 0;
}
