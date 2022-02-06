#include "masscan-app.h"
#include "masscan-status.h"
#include "output.h"
#include "string_s.h"

#include <ctype.h>

/****************************************************************************
 ****************************************************************************/
static void cert_out_open(struct Output *out) { UNUSEDPARM(out); }

/****************************************************************************
 ****************************************************************************/
static void cert_out_close(struct Output *out) {
  fprintf(out->fp, "{finished: 1}\n");
}

/******************************************************************************
 ******************************************************************************/
static void cert_out_status(struct Output *out, time_t timestamp,
                            enum PortStatus status, const ipaddress *ip,
                            unsigned ip_proto, unsigned port, unsigned reason,
                            unsigned ttl) {

  /* certificates only come with banner info, so there is no port info
   * to report */
  UNUSEDPARM(out);
  UNUSEDPARM(timestamp);
  UNUSEDPARM(status);
  UNUSEDPARM(ip);
  UNUSEDPARM(ip_proto);
  UNUSEDPARM(port);
  UNUSEDPARM(reason);
  UNUSEDPARM(ttl);
}

/******************************************************************************
 ******************************************************************************/
static void cert_out_banner(struct Output *out, time_t timestamp,
                            const ipaddress *ip, unsigned ip_proto,
                            unsigned port, enum ApplicationProtocol proto,
                            unsigned ttl, const unsigned char *px,
                            size_t length) {

  size_t i;
  UNUSEDPARM(ip_proto);
  UNUSEDPARM(ip);
  UNUSEDPARM(timestamp);
  UNUSEDPARM(out);
  UNUSEDPARM(ttl);
  UNUSEDPARM(proto);
  UNUSEDPARM(port);

  if (length > 5 && memcmp(px, "cert:", 5) == 0) {
    px += 5;
    length -= 5;
  }

  printf("-----BEGIN CERTIFICATE-----\n");
  for (i = 0; i < length; i += 72) {
    size_t len = length - i;
    if (len > 72) {
      len = 72;
    }
    printf("%.*s\n", (int)len, px + i);
  }
  printf("-----END CERTIFICATE-----\n");
}

static void cert_out_sign(struct Output *out, time_t timestamp,
                          const ipaddress *ip, unsigned ip_proto, unsigned port,
                          enum ApplicationProtocol proto) {

  UNUSEDPARM(ip_proto);
  UNUSEDPARM(ip);
  UNUSEDPARM(timestamp);
  UNUSEDPARM(out);
  UNUSEDPARM(proto);
  UNUSEDPARM(port);
}

/****************************************************************************
 ****************************************************************************/
const struct OutputType certs_output = {"cert",          NULL,
                                        cert_out_open,   cert_out_close,
                                        cert_out_status, cert_out_banner,
                                        cert_out_sign};
