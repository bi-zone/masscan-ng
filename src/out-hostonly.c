#include "masscan-app.h"
#include "masscan-status.h"
#include "masscan.h"
#include "out-tcp-services.h"
#include "output.h"
#include "util-cross.h"

static void hostonly_out_open(struct Output *out) { UNUSEDPARM(out); }

static void hostonly_out_close(struct Output *out) { UNUSEDPARM(out); }

static void hostonly_out_status(struct Output *out, time_t timestamp,
                                enum PortStatus status, const ipaddress *ip,
                                unsigned ip_proto, unsigned port,
                                unsigned reason, unsigned ttl) {

  ipaddress_formatted_t fmt;
  ipaddress_fmt(&fmt, ip);
  UNUSEDPARM(reason);
  UNUSEDPARM(timestamp);
  UNUSEDPARM(status);
  UNUSEDPARM(ip_proto);
  UNUSEDPARM(port);
  UNUSEDPARM(ttl);
  fprintf(out->fp, "%s\n", fmt.string);
}

/****************************************************************************
 ****************************************************************************/
static void hostonly_out_banner(struct Output *out, time_t timestamp,
                                const ipaddress *ip, unsigned ip_proto,
                                unsigned port, enum ApplicationProtocol proto,
                                unsigned ttl, const unsigned char *px,
                                size_t length) {

  ipaddress_formatted_t fmt;
  ipaddress_fmt(&fmt, ip);
  UNUSEDPARM(ttl);
  UNUSEDPARM(port);
  UNUSEDPARM(timestamp);
  UNUSEDPARM(ip_proto);
  UNUSEDPARM(proto);
  UNUSEDPARM(px);
  UNUSEDPARM(length);
  /* SYN only - no banner */
  fprintf(out->fp, "%s\n", fmt.string);
  return;
}

/****************************************************************************
 ****************************************************************************/
const struct OutputType hostonly_output = {"hostonly",
                                           NULL,
                                           hostonly_out_open,
                                           hostonly_out_close,
                                           hostonly_out_status,
                                           hostonly_out_banner,
                                           NULL};
