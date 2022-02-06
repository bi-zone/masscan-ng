#include "masscan-app.h"
#include "masscan-status.h"
#include "masscan-version.h"
#include "output.h"
#include "string_s.h"

/****************************************************************************
 ****************************************************************************/
static void xml_out_open(struct Output *out) {

  fprintf(out->fp, "<?xml version=\"1.0\"?>\r\n");
  fprintf(out->fp, "<!-- " MASSCAN_NAME " v" MASSCAN_VERSION " scan -->\r\n");
  if (out->xml.stylesheet && out->xml.stylesheet[0]) {
    fprintf(out->fp, "<?xml-stylesheet href=\"%s\" type=\"text/xsl\"?>\r\n",
            out->xml.stylesheet);
  }
  fprintf(out->fp,
          "<nmaprun scanner=\"" MASSCAN_NAME "\" start=\"%" PRIu64 "\" "
          "version=\"" MASSCAN_VERSION "\"  xmloutputversion=\"1.0\">\r\n",
          time(0));
  fprintf(out->fp, "<scaninfo type=\"%s\" protocol=\"%s\" />\r\n", "syn",
          "tcp");
}

/****************************************************************************
 ****************************************************************************/
static void xml_out_close(struct Output *out) {
  char buffer[256];
  time_t now = time(0);
  struct tm tm;

  if (out->is_gmt)
    gmtime_s(&tm, &now);
  else
    localtime_s(&tm, &now);
  if (strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm) == 0) {
    buffer[0] = 0;
  }

  fprintf(out->fp,
          "<runstats>\r\n"
          "<finished time=\"%" PRId64 "\" timestr=\"%s\" elapsed=\"%" PRId64
          "\" />\r\n"
          "<hosts up=\"%" PRIu64 "\" down=\"%" PRIu64 "\" total=\"%" PRIu64
          "\" />\r\n"
          "</runstats>\r\n"
          "</nmaprun>\r\n",
          (int64_t)now /* time */, buffer /* timestr */,
          (int64_t)(now - out->rotate.last) /* elapsed */, out->counts.tcp.open,
          out->counts.tcp.closed,
          out->counts.tcp.open + out->counts.tcp.closed);
}

/****************************************************************************
 ****************************************************************************/
static void xml_out_status(struct Output *out, time_t timestamp,
                           enum PortStatus status, const ipaddress *ip,
                           unsigned ip_proto, unsigned port, unsigned reason,
                           unsigned ttl) {

  char reason_buffer[128];
  ipaddress_formatted_t fmt;
  ipaddress_fmt(&fmt, ip);
  fprintf(out->fp,
          "<host endtime=\"%" PRId64 "\">"
          "<address addr=\"%s\" addrtype=\"ipv%u\"/>"
          "<ports>"
          "<port protocol=\"%s\" portid=\"%u\">"
          "<state state=\"%s\" reason=\"%s\" reason_ttl=\"%u\"/>"
          "</port>"
          "</ports>"
          "</host>\r\n",
          (int64_t)timestamp, fmt.string, ip->version,
          name_from_ip_proto(ip_proto), port, status_string(status),
          reason_string(reason, reason_buffer, sizeof(reason_buffer)), ttl);
}

/****************************************************************************
 ****************************************************************************/
static void xml_out_banner(struct Output *out, time_t timestamp,
                           const ipaddress *ip, unsigned ip_proto,
                           unsigned port, enum ApplicationProtocol proto,
                           unsigned ttl, const unsigned char *px,
                           size_t length) {

  char banner_buffer[4096];
  const char *reason;
  ipaddress_formatted_t fmt;
  ipaddress_fmt(&fmt, ip);

  switch (proto) {
  case 6:
    reason = "syn-ack";
    break;
  default:
    reason = "response";
    break;
  }

  fprintf(out->fp,
          "<host endtime=\"%" PRId64 "\">"
          "<address addr=\"%s\" addrtype=\"ipv%u\"/>"
          "<ports>"
          "<port protocol=\"%s\" portid=\"%u\">"
          "<state state=\"open\" reason=\"%s\" reason_ttl=\"%u\" />"
          "<service name=\"%s\" banner=\"%s\"></service>"
          "</port>"
          "</ports>"
          "</host>\r\n",
          (int64_t)timestamp, fmt.string, ip->version,
          name_from_ip_proto(ip_proto), port, reason, ttl,
          masscan_app_to_string(proto),
          normalize_string(px, length, banner_buffer, sizeof(banner_buffer)));
}

static void xml_out_sign(struct Output *out, time_t timestamp,
                         const ipaddress *ip, unsigned ip_proto, unsigned port,
                         enum ApplicationProtocol proto) {

  ipaddress_formatted_t fmt;
  ipaddress_fmt(&fmt, ip);
  fprintf(out->fp,
          "<host endtime=\"%" PRId64 "\">"
          "<address addr=\"%s\" addrtype=\"ipv%u\"/>"
          "<ports>"
          "<port protocol=\"%s\" portid=\"%u\">"
          "<service name=\"%s\"></service>"
          "</port>"
          "</ports>"
          "</host>\r\n",
          (int64_t)timestamp, fmt.string, ip->version,
          name_from_ip_proto(ip_proto), port, masscan_app_to_string(proto));
}

/****************************************************************************
 ****************************************************************************/
const struct OutputType xml_output = {
    "xml",          NULL,           xml_out_open, xml_out_close,
    xml_out_status, xml_out_banner, xml_out_sign};
