#include "in-filter.h"
#include "masscan-app.h"
#include "massip.h"

int readscan_filter_pass(const ipaddress *ip, unsigned port,
                         enum ApplicationProtocol type,
                         const struct MassIP *filter,
                         const struct RangeList *btypes) {

  if (filter && filter->count_ipv4s) {
    if (!massip_has_ip(filter, ip))
      return 0;
  }
  if (filter && filter->count_ports) {
    if (!massip_has_port(filter, port))
      return 0;
  }
  unsigned unsigent_type = type;
  if (btypes && btypes->count) {
    if (!rangelist_is_contains(btypes, &unsigent_type))
      return 0;
  }

  return 1;
}
