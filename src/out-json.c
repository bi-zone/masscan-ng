#include "masscan-app.h"
#include "masscan-status.h"
#include "output.h"
#include "string_s.h"

#include <ctype.h>

/****************************************************************************
 ****************************************************************************/
static void json_out_open(struct Output *out) {
  fprintf(out->fp, "[\n"); // enclose the atomic {}'s into an []
}

/****************************************************************************
 ****************************************************************************/
static void json_out_close(struct Output *out) {
  fprintf(out->fp, "]\n"); // enclose the atomic {}'s into an []
}

//{ ip: "124.53.139.201", ports: [ {port: 443, proto: "tcp", status: "open",
//reason: "syn-ack", ttl: 48} ] }
/****************************************************************************
 ****************************************************************************/
static void json_out_status(struct Output *out, time_t timestamp,
                            enum PortStatus status, const ipaddress *ip,
                            unsigned ip_proto, unsigned port, unsigned reason,
                            unsigned ttl) {

  char reason_buffer[128];
  ipaddress_formatted_t fmt;
  UNUSEDPARM(out);

  ipaddress_fmt(&fmt, ip);
  /* Trailing comma breaks some JSON parsers. We don't know precisely when
   * we'll end, but we do know when we begin, so instead of appending
   * a command to the record, we prepend it -- but not before first record */
  if (out->is_first_record_seen)
    fprintf(out->fp, ",\n");
  else
    out->is_first_record_seen = 1;

  fprintf(out->fp, "{ ");
  fprintf(out->fp, "  \"ip\": \"%s\", ", fmt.string);
  fprintf(out->fp,
          "  \"timestamp\": \"%" PRId64 "\", \"ports\": [ {\"port\": %u,"
          " \"proto\": \"%s\", \"status\": \"%s\", \"reason\": \"%s\", "
          "\"ttl\": %u} ] ",
          (int64_t)timestamp, port, name_from_ip_proto(ip_proto),
          status_string(status),
          reason_string(reason, reason_buffer, sizeof(reason_buffer)), ttl);
  fprintf(out->fp, "}\n");
}

/*****************************************************************************
 * Remove bad characters from the banner, especially new lines and HTML
 * control codes.
 *****************************************************************************/
static const char *normalize_json_string(const unsigned char *px, size_t length,
                                         char *buf, size_t buf_len) {

  size_t i = 0;
  size_t offset = 0;

  for (i = 0; i < length; i++) {
    unsigned char c = px[i];

    if (isprint(c) && c != '<' && c != '>' && c != '&' && c != '\\' &&
        c != '\"' && c != '\'') {
      if (offset + 2 < buf_len)
        buf[offset++] = px[i];
    } else {
      if (offset + 7 < buf_len) {
        buf[offset++] = '\\';
        buf[offset++] = 'u';
        buf[offset++] = '0';
        buf[offset++] = '0';
        buf[offset++] = "0123456789abcdef"[px[i] >> 4];
        buf[offset++] = "0123456789abcdef"[px[i] & 0xF];
      }
    }
  }
  buf[offset] = '\0';

  return buf;
}

/******************************************************************************
 ******************************************************************************/
static void json_out_banner(struct Output *out, time_t timestamp,
                            const ipaddress *ip, unsigned ip_proto,
                            unsigned port, enum ApplicationProtocol proto,
                            unsigned ttl, const unsigned char *px,
                            size_t length) {

  ipaddress_formatted_t fmt;
  char banner_buffer[65536];
  UNUSEDPARM(ttl);

  ipaddress_fmt(&fmt, ip);
  /* Trailing comma breaks some JSON parsers. We don't know precisely when
   * we'll end, but we do know when we begin, so instead of appending
   * a command to the record, we prepend it -- but not before first record */
  if (out->is_first_record_seen)
    fprintf(out->fp, ",\n");
  else
    out->is_first_record_seen = 1;

  fprintf(out->fp, "{ ");
  fprintf(out->fp, "  \"ip\": \"%s\", ", fmt.string);
  fprintf(
      out->fp,
      "  \"timestamp\": \"%" PRId64 "\", \"ports\": [ {\"port\": %u,"
      " \"proto\": \"%s\", \"service\": {\"name\": \"%s\", \"banner\": \"%s\"} "
      "} ] ",
      (int64_t)timestamp, port, name_from_ip_proto(ip_proto),
      masscan_app_to_string(proto),
      normalize_json_string(px, length, banner_buffer, sizeof(banner_buffer)));
  fprintf(out->fp, "}\n");
}

static void json_out_sign(struct Output *out, time_t timestamp,
                          const ipaddress *ip, unsigned ip_proto, unsigned port,
                          enum ApplicationProtocol proto) {

  ipaddress_formatted_t fmt;
  ipaddress_fmt(&fmt, ip);

  /* Trailing comma breaks some JSON parsers. We don't know precisely when
   * we'll end, but we do know when we begin, so instead of appending
   * a command to the record, we prepend it -- but not before first record */
  if (out->is_first_record_seen)
    fprintf(out->fp, ",\n");
  else
    out->is_first_record_seen = 1;

  fprintf(out->fp, "{ ");
  fprintf(out->fp, "  \"ip\": \"%s\", ", fmt.string);
  fprintf(out->fp,
          "  \"timestamp\": \"%" PRId64 "\", \"ports\": [ {\"port\": %u,"
          " \"proto\": \"%s\", \"sign\": {\"name\": \"%s\"} } ] ",
          (int64_t)timestamp, port, name_from_ip_proto(ip_proto),
          masscan_app_to_string(proto));
  fprintf(out->fp, "}\n");
}

/****************************************************************************
 ****************************************************************************/
const struct OutputType json_output = {"json",          NULL,
                                       json_out_open,   json_out_close,
                                       json_out_status, json_out_banner,
                                       json_out_sign};
