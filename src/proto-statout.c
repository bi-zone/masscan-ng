#include "proto-statout.h"
#include "masscan-status.h"
#include "util-cross.h"
#include "util-malloc.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void statout_init(struct StatusOutput *statout) {
  memset(statout, 0, sizeof(*statout));
  statout->is_empty = true;
}

void statout_release(struct StatusOutput *statout) {
  while (statout->next) {
    struct StatusOutput *next = statout->next->next;
    free(statout->next);
    statout->next = next;
  }
  statout_init(statout);
}

struct StatusOutput *statout_new_status(struct StatusOutput *statout,
                                        time_t timestamp, int status,
                                        unsigned reason, unsigned ttl,
                                        const unsigned char mac[6]) {
  struct StatusOutput *p;

  if (statout->is_empty) {
    statout->is_empty = false;
    statout->timestamp = timestamp;
    statout->status = status;
    statout->reason = reason;
    statout->ttl = ttl;
    if (mac != NULL) {
      memcpy(statout->mac, mac, sizeof(statout->mac));
    }
    return statout;
  }

  p = CALLOC(1, sizeof(*p));
  p->timestamp = timestamp;
  p->status = status;
  p->reason = reason;
  p->ttl = ttl;
  if (mac != NULL) {
    memcpy(p->mac, mac, sizeof(p->mac));
  }
  p->next = statout->next;
  statout->next = p;
  return p;
}

static size_t statout_count(const struct StatusOutput *statout) {
  size_t count = 0;
  while (statout && statout->is_empty == false) {
    count += 1;
    statout = statout->next;
  }

  return count;
}

int statout_selftest(void) {
  /*
   * Basic test
   */
  {
    struct StatusOutput statout[1];
    unsigned i;
    unsigned char mac[6] = {1, 1, 1, 1, 1, 1};

    statout_init(statout);
    if (statout_count(statout) != 0) {
      return 1;
    }

    for (i = 0; i < 10; i++) {
      statout_new_status(statout, time(0), PortStatus_Open, 1, 1, mac);
      statout_new_status(statout, time(0), PortStatus_Closed, 2, 2, mac);
    }
    if (statout->next == NULL) {
      return 1;
    }
    if (statout_count(statout) != 20) {
      return 1;
    }

    statout_release(statout);
    if (statout->next != NULL) {
      return 1;
    }
    if (statout_count(statout) != 0) {
      return 1;
    }
  }

  {
    struct StatusOutput statout[1];
    unsigned char mac1[6] = {4, 4, 4, 4, 4, 4};
    unsigned char mac2[6] = {6, 6, 6, 6, 6, 6};

    statout_init(statout);
    statout_new_status(statout, time(0), PortStatus_Open, 2, 3, mac1);
    statout_new_status(statout, time(0), PortStatus_Closed, 4, 5, mac2);

    if (statout->is_empty != false) {
      return 1;
    }
    if (statout->status != PortStatus_Open) {
      return 1;
    }
    if (statout->reason != 2) {
      return 1;
    }
    if (statout->ttl != 3) {
      return 1;
    }
    if (memcmp(statout->mac, mac1, sizeof(mac1)) != 0) {
      return 1;
    }
    if (statout->next == NULL) {
      return 1;
    }

    if (statout->next->is_empty != false) {
      return 1;
    }
    if (statout->next->status != PortStatus_Closed) {
      return 1;
    }
    if (statout->next->reason != 4) {
      return 1;
    }
    if (statout->next->ttl != 5) {
      return 1;
    }
    if (memcmp(statout->next->mac, mac2, sizeof(mac2)) != 0) {
      return 1;
    }
    if (statout->next->next != NULL) {
      return 1;
    }

    statout_release(statout);
  }

  return 0;
}
