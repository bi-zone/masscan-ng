#ifndef PROTO_STATOUT_H
#define PROTO_STATOUT_H

#include <time.h>

struct StatusOutput {
  struct StatusOutput *next;
  unsigned is_empty : 1;
  time_t timestamp;
  int status;
  unsigned reason;
  unsigned ttl;
  unsigned char mac[6];
};

void statout_init(struct StatusOutput *statout);
void statout_release(struct StatusOutput *statout);
struct StatusOutput *statout_new_status(struct StatusOutput *statout,
                                        time_t timestamp, int status,
                                        unsigned reason, unsigned ttl,
                                        const unsigned char mac[6]);
int statout_selftest(void);

#endif // PROTO_STATOUT_H
