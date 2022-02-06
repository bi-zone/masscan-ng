#include "proto-oproto.h"
#include "util-cross.h"

void handle_oproto(struct Output *out, time_t timestamp,
                   const unsigned char *px, size_t length,
                   struct PreprocessedInfo *parsed, uint64_t entropy) {
  UNUSEDPARM(out);
  UNUSEDPARM(timestamp);
  UNUSEDPARM(px);
  UNUSEDPARM(length);
  UNUSEDPARM(parsed);
  UNUSEDPARM(entropy);
}
