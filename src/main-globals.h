#ifndef MAIN_GLOBALS_H
#define MAIN_GLOBALS_H

#include <time.h>

#include "util-cross.h"

extern bool volatile is_tx_done;
extern bool volatile is_rx_done;
extern time_t volatile global_now;

#endif
