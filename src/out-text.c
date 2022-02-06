#include "masscan-app.h"
#include "masscan-status.h"
#include "masscan.h"
#include "output.h"
#include "util-cross.h"

#include <ctype.h>

/****************************************************************************
 ****************************************************************************/
static void text_out_open(struct Output *out) {
  fprintf(out->fp, "#masscan\n");
}

/****************************************************************************
 ****************************************************************************/
static void text_out_close(struct Output *out) { fprintf(out->fp, "# end\n"); }

/****************************************************************************
 ****************************************************************************/
static void text_out_status(struct Output *out, time_t timestamp,
                            enum PortStatus status, const ipaddress *ip,
                            unsigned ip_proto, unsigned port, unsigned reason,
                            unsigned ttl) {

  ipaddress_formatted_t fmt;
  UNUSEDPARM(ttl);
  UNUSEDPARM(reason);
  ipaddress_fmt(&fmt, ip);
  fprintf(out->fp, "%s %s %u %s %" PRId64 "\n", status_string(status),
          name_from_ip_proto(ip_proto), port, fmt.string, (int64_t)timestamp);
}

/****************************************************************************
 ****************************************************************************/
static void text_out_banner(struct Output *out, time_t timestamp,
                            const ipaddress *ip, unsigned ip_proto,
                            unsigned port, enum ApplicationProtocol proto,
                            unsigned ttl, const unsigned char *px,
                            size_t length) {

  char banner_buffer[4096];
  ipaddress_formatted_t fmt;
  UNUSEDPARM(ttl);

  ipaddress_fmt(&fmt, ip);
  fprintf(out->fp, "%s %s %u %s %" PRId64 " %s %s\n", "banner",
          name_from_ip_proto(ip_proto), port, fmt.string, (int64_t)timestamp,
          masscan_app_to_string(proto),
          normalize_string(px, length, banner_buffer, sizeof(banner_buffer)));
}

static void text_out_sign(struct Output *out, time_t timestamp,
                          const ipaddress *ip, unsigned ip_proto, unsigned port,
                          enum ApplicationProtocol proto) {

  ipaddress_formatted_t fmt;
  ipaddress_fmt(&fmt, ip);
  fprintf(out->fp, "%s %s %u %s %" PRId64 " %s\n", "sign",
          name_from_ip_proto(ip_proto), port, fmt.string, (int64_t)timestamp,
          masscan_app_to_string(proto));
}

/****************************************************************************
 ****************************************************************************/
const struct OutputType text_output = {"txt",           NULL,
                                       text_out_open,   text_out_close,
                                       text_out_status, text_out_banner,
                                       text_out_sign};
