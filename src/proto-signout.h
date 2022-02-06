#ifndef PROTO_SIGNOUT_H
#define PROTO_SIGNOUT_H

#include <time.h>

#include "masscan-app.h"

struct SignOutput {
  struct SignOutput *next;
  unsigned is_empty : 1;
  time_t timestamp;
  enum ApplicationProtocol app_proto;
};

void signout_init(struct SignOutput *signout);
void signout_release(struct SignOutput *signout);
struct SignOutput *signout_new_sign(struct SignOutput *signout,
                                    time_t timestamp,
                                    enum ApplicationProtocol app_proto);
int signout_selftest(void);

#endif // PROTO_STATOUT_H
