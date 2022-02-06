#ifndef PROTO_KEYOUT_H
#define PROTO_KEYOUT_H

#include <time.h>

#include "masscan-app.h"

struct KeyOutput {
  struct KeyOutput *next;
  char line[1];
};

void keyout_init(struct KeyOutput **keyout);
void keyout_release(struct KeyOutput **keyout);
struct KeyOutput *keyout_new_line(struct KeyOutput **keyout, const char *line);
int keyout_selftest(void);

#endif // PROTO_STATOUT_H
