#include "masscan-app.h"
#include "masscan-status.h"
#include "masscan.h"
#include "out-tcp-services.h"
#include "output.h"
#include "util-cross.h"

static void unicornscan_out_open(struct Output *out) {
  fprintf(out->fp, "#masscan\n");
}

static void unicornscan_out_close(struct Output *out) {
  fprintf(out->fp, "# end\n");
}

static void unicornscan_out_status(struct Output *out, time_t timestamp,
                                   enum PortStatus status, const ipaddress *ip,
                                   unsigned ip_proto, unsigned port,
                                   unsigned reason, unsigned ttl) {

  ipaddress_formatted_t fmt;
  UNUSEDPARM(reason);
  UNUSEDPARM(timestamp);

  ipaddress_fmt(&fmt, ip);

  if (ip_proto == 6) {
    fprintf(out->fp, "TCP %s\t%16s[%5u]\t\tfrom %s  ttl %-3u\n",
            status_string(status), tcp_service_name(port), port, fmt.string,
            ttl);
  } else {
    /* unicornscan is TCP only, so just use grepable format for other protocols
     */
    fprintf(out->fp, "Host: %s ()", fmt.string);
    fprintf(out->fp, "\tPorts: %u/%s/%s/%s/%s/%s/%s\n", port,
            status_string(status),        //"open", "closed"
            name_from_ip_proto(ip_proto), //"tcp", "udp", "sctp"
            "" /* owner */, "" /* service */, "" /* SunRPC info */,
            "" /* Version info */);
  }
}

/****************************************************************************
 ****************************************************************************/
static void unicornscan_out_banner(struct Output *out, time_t timestamp,
                                   const ipaddress *ip, unsigned ip_proto,
                                   unsigned port,
                                   enum ApplicationProtocol proto, unsigned ttl,
                                   const unsigned char *px, size_t length) {

  /* SYN only - no banner */
  UNUSEDPARM(out);
  UNUSEDPARM(ttl);
  UNUSEDPARM(port);
  UNUSEDPARM(timestamp);
  UNUSEDPARM(ip);
  UNUSEDPARM(ip_proto);
  UNUSEDPARM(proto);
  UNUSEDPARM(px);
  UNUSEDPARM(length);
  return;
}

static void unicornscan_out_sign(struct Output *out, time_t timestamp,
                                 const ipaddress *ip, unsigned ip_proto,
                                 unsigned port,
                                 enum ApplicationProtocol proto) {

  /* SYN only - no banner */
  UNUSEDPARM(out);
  UNUSEDPARM(port);
  UNUSEDPARM(timestamp);
  UNUSEDPARM(ip);
  UNUSEDPARM(ip_proto);
  UNUSEDPARM(proto);
  return;
}

/****************************************************************************
 ****************************************************************************/
const struct OutputType unicornscan_output = {"uni",
                                              NULL,
                                              unicornscan_out_open,
                                              unicornscan_out_close,
                                              unicornscan_out_status,
                                              unicornscan_out_banner,
                                              unicornscan_out_sign};
