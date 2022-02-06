#include "proto-arp.h"
#include "logger.h"
#include "masscan-status.h"
#include "output.h"
#include "proto-preprocess.h"
#include "util-cross.h"

/***************************************************************************
 * Process an ARP packet received in response to an ARP-scan.
 ***************************************************************************/
void arp_recv_response(struct Output *out, time_t timestamp,
                       const unsigned char *px, size_t length,
                       struct PreprocessedInfo *parsed) {

  ipaddress ip_them = parsed->src_ip;
  ipaddress_formatted_t fmt;
  ipaddress_fmt(&fmt, &ip_them);
  UNUSEDPARM(length);
  UNUSEDPARM(px);
  LOG(LEVEL_DEBUG_1, "ARP %s = [%02X:%02X:%02X:%02X:%02X:%02X]\n", fmt.string,
      parsed->mac_src[0], parsed->mac_src[1], parsed->mac_src[2],
      parsed->mac_src[3], parsed->mac_src[4], parsed->mac_src[5]);

  output_report_status(out, timestamp, PortStatus_Arp, &ip_them,
                       0 /* ip proto */, 0, 0, 0, parsed->mac_src);
}
