#ifndef masscan_main_ptrace_h
#define masscan_main_ptrace_h
#include <stdint.h>
#include <stdio.h>

void packet_trace(FILE *fp, double pt_trace, const unsigned char *px,
                  size_t length, unsigned is_sent);

#endif
