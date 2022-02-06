#include "proto-keyout.h"
#include "logger.h"
#include "string_s.h"
#include "util-cross.h"
#include "util-malloc.h"
#include "util-test.h"

#include <stddef.h>
#include <time.h>

void keyout_init(struct KeyOutput **keyout) { *keyout = NULL; }

void keyout_release(struct KeyOutput **keyout) {
  while (*keyout) {
    struct KeyOutput *next = (*keyout)->next;
    free(*keyout);
    *keyout = next;
  }
}

struct KeyOutput *keyout_new_line(struct KeyOutput **keyout, const char *line) {

  struct KeyOutput *p;
  size_t len_line = strlen(line);
  p = MALLOC(sizeof(*p) + len_line);
  p->next = *keyout;
  strcpy_s(p->line, len_line + 1, line);
  *keyout = p;
  return p;
}

static size_t keyout_count(const struct KeyOutput *keyout) {
  size_t count = 0;
  while (keyout) {
    count += 1;
    keyout = keyout->next;
  }
  return count;
}

int keyout_selftest(void) {
  /* Basic test */
  {
    struct KeyOutput *keyout = NULL;
    REGRESS(keyout_count(keyout) == 0);

    keyout_new_line(&keyout, "KEY1");
    REGRESS(keyout != NULL);
    REGRESS(keyout->next == NULL);
    REGRESS(keyout_count(keyout) == 1);
    keyout_new_line(&keyout, "KEY2");
    REGRESS(keyout != NULL);
    REGRESS(keyout->next != NULL);
    REGRESS(keyout_count(keyout) == 2);

    keyout_release(&keyout);
    REGRESS(keyout == NULL);
    REGRESS(keyout_count(keyout) == 0);
  }
  return 0;
}
