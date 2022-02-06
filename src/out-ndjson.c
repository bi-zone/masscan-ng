#include "masscan-app.h"
#include "masscan-status.h"
#include "output.h"
#include "string_s.h"

#include <ctype.h>

/****************************************************************************
 ****************************************************************************/
static void ndjson_out_open(struct Output *out) { UNUSEDPARM(out); }

/****************************************************************************
 ****************************************************************************/
static void ndjson_out_close(struct Output *out) { UNUSEDPARM(out); }

//{ ip: "124.53.139.201", ports: [ {port: 443, proto: "tcp", status: "open",
//reason: "syn-ack", ttl: 48} ] }
/****************************************************************************
 ****************************************************************************/
static void ndjson_out_status(struct Output *out, time_t timestamp,
                              enum PortStatus status, const ipaddress *ip,
                              unsigned ip_proto, unsigned port, unsigned reason,
                              unsigned ttl) {

  ipaddress_formatted_t fmt;
  char reason_buffer[128];

  ipaddress_fmt(&fmt, ip);
  fprintf(out->fp, "{");
  fprintf(out->fp, "\"ip\":\"%s\",", fmt.string);
  fprintf(
      out->fp,
      "\"timestamp\":\"%" PRId64 "\",\"port\":%u,"
      "\"proto\":\"%s\",\"rec_type\":\"status\",\"data\":{\"status\":\"%s\","
      "\"reason\":\"%s\",\"ttl\":%u}",
      (int64_t)timestamp, port, name_from_ip_proto(ip_proto),
      status_string(status),
      reason_string(reason, reason_buffer, sizeof(reason_buffer)), ttl);
  fprintf(out->fp, "}\n");
}

/*****************************************************************************
 * Remove bad characters from the banner, especially new lines and HTML
 * control codes.
 *
 * Keeping this here since we may need to change the behavior from what
 * is done in the sister `normalize_json_string` function. It's unlikely
 * but it's a small function and will save time later if needed. Could also
 * set it up to base64 encode the banner payload.
 *****************************************************************************/
static const char *normalize_ndjson_string(const unsigned char *px,
                                           size_t length, char *buf,
                                           size_t buf_len) {

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
static void ndjson_out_banner(struct Output *out, time_t timestamp,
                              const ipaddress *ip, unsigned ip_proto,
                              unsigned port, enum ApplicationProtocol proto,
                              unsigned ttl, const unsigned char *px,
                              size_t length) {

  ipaddress_formatted_t fmt;
  char banner_buffer[65536];
  UNUSEDPARM(ttl);

  ipaddress_fmt(&fmt, ip);
  fprintf(out->fp, "{");
  fprintf(out->fp, "\"ip\":\"%s\",", fmt.string);
  fprintf(out->fp,
          "\"timestamp\":\"%" PRId64 "\",\"port\":%u,"
          "\"proto\":\"%s\",\"rec_type\":\"banner\",\"data\":"
          "{\"service_name\":\"%s\",\"banner\":\"%s\"}",
          (int64_t)timestamp, port, name_from_ip_proto(ip_proto),
          masscan_app_to_string(proto),
          normalize_ndjson_string(px, length, banner_buffer,
                                  sizeof(banner_buffer)));

  fprintf(out->fp, "}\n");
}

static void ndjson_out_sign(struct Output *out, time_t timestamp,
                            const ipaddress *ip, unsigned ip_proto,
                            unsigned port, enum ApplicationProtocol proto) {

  ipaddress_formatted_t fmt;
  ipaddress_fmt(&fmt, ip);
  fprintf(out->fp, "{");
  fprintf(out->fp, "\"ip\":\"%s\",", fmt.string);
  fprintf(out->fp,
          "\"timestamp\":\"%" PRId64 "\",\"port\":%u,"
          "\"proto\":\"%s\",\"rec_type\":\"sign\",\"data\":"
          "{\"sign_name\":\"%s\"}",
          (int64_t)timestamp, port, name_from_ip_proto(ip_proto),
          masscan_app_to_string(proto));
  fprintf(out->fp, "}\n");
}

/****************************************************************************
 ****************************************************************************/
const struct OutputType ndjson_output = {"ndjson",          NULL,
                                         ndjson_out_open,   ndjson_out_close,
                                         ndjson_out_status, ndjson_out_banner,
                                         ndjson_out_sign};
