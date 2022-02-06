#include "masscan-status.h"
#include "masscan-version.h"
#include "masscan.h"
#include "massip-port.h"
#include "out-tcp-services.h"
#include "output.h"
#include "string_s.h"

/****************************************************************************
 ****************************************************************************/
static unsigned count_type(const struct RangeList *ports, int start_type,
                           int end_type) {

  unsigned min_port = start_type;
  unsigned max_port = end_type;
  size_t i;
  unsigned result = 0;

  for (i = 0; i < ports->count; i++) {
    struct Range r = ports->list[i];
    if (r.begin > max_port)
      continue;
    if (r.end < min_port)
      continue;

    if (r.begin < min_port)
      r.begin = min_port;
    if (r.end > max_port)
      r.end = max_port;

    result += r.end - r.begin + 1;
  }
  return result;
}

/****************************************************************************
 ****************************************************************************/
static void print_port_list(const struct RangeList *ports, int type, FILE *fp) {
  unsigned min_port = type;
  unsigned max_port = type + 65535;
  size_t i;

  for (i = 0; i < ports->count; i++) {
    struct Range r = ports->list[i];
    if (r.begin > max_port)
      continue;
    if (r.end < min_port)
      continue;
    if (r.begin < min_port)
      r.begin = min_port;
    if (r.end > max_port)
      r.end = max_port;
    fprintf(fp, "%u-%u%s", r.begin, r.end, (i + 1 < ports->count) ? "," : "");
  }
}

extern const char *debug_recv_status;

/****************************************************************************
 * This function doesn't really "open" the file. Instead, the purpose of
 * this function is to initialize the file by printing header information.
 ****************************************************************************/
static void grepable_out_open(struct Output *out) {
  char timestamp[64];
  struct tm tm;
  unsigned count;

  gmtime_s(&tm, &out->when_scan_started);

  // Tue Jan 21 20:23:22 2014
  //%a %b %d %H:%M:%S %Y
  if (strftime(timestamp, sizeof(timestamp), "%c", &tm) == 0) {
    timestamp[0] = '\0';
  }

  fprintf(out->fp, "# " MASSCAN_NAME " " MASSCAN_VERSION " scan initiated %s\n",
          timestamp);

  count = count_type(&out->masscan->targets.ports, Templ_TCP, Templ_TCP_last);
  fprintf(out->fp, "# Ports scanned: TCP(%u;", count);
  if (count)
    print_port_list(&out->masscan->targets.ports, Templ_TCP, out->fp);

  count = count_type(&out->masscan->targets.ports, Templ_UDP, Templ_UDP_last);
  fprintf(out->fp, ") UDP(%u;", count);
  if (count)
    print_port_list(&out->masscan->targets.ports, Templ_UDP, out->fp);

  count = count_type(&out->masscan->targets.ports, Templ_SCTP, Templ_SCTP_last);
  fprintf(out->fp, ") SCTP(%u;", count);
  if (count)
    print_port_list(&out->masscan->targets.ports, Templ_SCTP, out->fp);

  count =
      count_type(&out->masscan->targets.ports, Templ_Oproto, Templ_Oproto_last);
  fprintf(out->fp, ") PROTOCOLS(%u;", count);
  if (count)
    print_port_list(&out->masscan->targets.ports, Templ_Oproto, out->fp);

  fprintf(out->fp, ")\n");
}

/****************************************************************************
 * This function doesn't really "close" the file. Instead, it's purpose
 * is to print trailing information to the file. This is pretty much only
 * a concern for XML files that need stuff appended to the end.
 ****************************************************************************/
static void grepable_out_close(struct Output *out) {
  time_t now = time(0);
  char timestamp[64];
  struct tm tm;

  gmtime_s(&tm, &now);

  // Tue Jan 21 20:23:22 2014
  //%a %b %d %H:%M:%S %Y
  if (strftime(timestamp, sizeof(timestamp), "%c", &tm) == 0) {
    timestamp[0] = '\0';
  }

  fprintf(out->fp, "# " MASSCAN_NAME " done at %s\n", timestamp);
}

/****************************************************************************
 * Prints out the status of a port, which is almost always just "open"
 * or "closed".
 ****************************************************************************/
static void grepable_out_status(struct Output *out, time_t timestamp,
                                enum PortStatus status, const ipaddress *ip,
                                unsigned ip_proto, unsigned port,
                                unsigned reason, unsigned ttl) {

  const char *service;
  ipaddress_formatted_t fmt;
  UNUSEDPARM(reason);
  UNUSEDPARM(ttl);

  ipaddress_fmt(&fmt, ip);

  if (ip_proto == 6)
    service = tcp_service_name(port);
  else if (ip_proto == 17)
    service = udp_service_name(port);
  else
    service = oproto_service_name(ip_proto);

  fprintf(out->fp, "Timestamp: %" PRId64, (int64_t)timestamp);
  fprintf(out->fp, "\tHost: %s ()", fmt.string);
  fprintf(out->fp, "\tPorts: %u/%s/%s/%s/%s/%s/%s\n", port,
          status_string(status),        //"open", "closed"
          name_from_ip_proto(ip_proto), //"tcp", "udp", "sctp"
          "" /* owner */, service /* service */, "" /* SunRPC info */,
          "" /* Version info */);
}

/****************************************************************************
 * Prints out "banner" information for a port. This is done when there is
 * a protocol defined for a port, and we do some interaction to find out
 * more information about which protocol is running on a port, it's version,
 * and other useful information.
 ****************************************************************************/
static void grepable_out_banner(struct Output *out, time_t timestamp,
                                const ipaddress *ip, unsigned ip_proto,
                                unsigned port, enum ApplicationProtocol proto,
                                unsigned ttl, const unsigned char *px,
                                size_t length) {

  char banner_buffer[4096];
  ipaddress_formatted_t fmt;
  UNUSEDPARM(ttl);
  UNUSEDPARM(ip_proto);

  ipaddress_fmt(&fmt, ip);

  fprintf(out->fp, "Timestamp: %" PRId64, (int64_t)timestamp);
  fprintf(out->fp, "\tHost: %s ()", fmt.string);
  fprintf(out->fp, "\tProtocols: %u/open/%s", port,
          name_from_ip_proto(ip_proto));
  fprintf(out->fp, "\tService: %s", masscan_app_to_string(proto));
  normalize_string(px, length, banner_buffer, sizeof(banner_buffer));
  fprintf(out->fp, "\tBanner: %s\n", banner_buffer);
}

static void grepable_out_sign(struct Output *out, time_t timestamp,
                              const ipaddress *ip, unsigned ip_proto,
                              unsigned port, enum ApplicationProtocol proto) {

  ipaddress_formatted_t fmt;
  ipaddress_fmt(&fmt, ip);

  fprintf(out->fp, "Timestamp: %" PRId64, (int64_t)timestamp);
  fprintf(out->fp, "\tHost: %s ()", fmt.string);
  fprintf(out->fp, "\tProtocols: %u/open/%s", port,
          name_from_ip_proto(ip_proto));
  fprintf(out->fp, "\tService: %s\n", masscan_app_to_string(proto));
}

/****************************************************************************
 * This is the only structure exposed to the rest of the system. Everything
 * else in the file is defined 'static' or 'private'.
 ****************************************************************************/
const struct OutputType grepable_output = {
    "grepable",          NULL,
    grepable_out_open,   grepable_out_close,
    grepable_out_status, grepable_out_banner,
    grepable_out_sign};
