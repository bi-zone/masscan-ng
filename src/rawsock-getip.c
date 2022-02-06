/*
    retrieve IPv4 address of the named network interface/adapter
    like "eth0"


    This works on:
        - Windows
        - Linux
        - Apple
        - FreeBSD

 I think it'll work the same on any BSD system.
*/
#include "logger.h"
#include "massip-parse.h"
#include "rawsock.h"
#include "string_s.h"

/*****************************************************************************
 *****************************************************************************/
#if defined(__linux__)
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

ipv4address_t *rawsock_get_adapter_ip(ipv4address_t *result,
                                      const char *ifname) {
  int fd;
  struct ifreq ifr;
  struct sockaddr_in *sin;
  struct sockaddr *sa;
  int x;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strcpy_s(ifr.ifr_name, IFNAMSIZ, ifname);

  x = ioctl(fd, SIOCGIFADDR, &ifr);
  if (x < 0) {
    LOG(LEVEL_ERROR, "ERROR:'%s': %s\n", ifname, strerror(errno));
    // LOG(LEVEL_ERROR, "ERROR:'%s': couldn't discover IP address of network
    // interface\n", ifname);
    close(fd);
    return 0;
  }

  close(fd);

  sa = &ifr.ifr_addr;
  sin = (struct sockaddr_in *)sa;
  *result = ntohl(sin->sin_addr.s_addr);
  return result;
}

/*****************************************************************************
 *****************************************************************************/
#elif defined(WIN32)
#include <winsock2.h>
#include <iphlpapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "IPHLPAPI.lib")
#endif

ipv4address_t *rawsock_get_adapter_ip(ipv4address_t *result,
                                      const char *ifname) {
  PIP_ADAPTER_INFO pAdapterInfo;
  PIP_ADAPTER_INFO pAdapter = NULL;
  DWORD err;
  ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

  *result = 0;

  ifname = rawsock_win_name(ifname);

  /* Allocate a proper sized buffer */
  pAdapterInfo = malloc(sizeof(IP_ADAPTER_INFO));
  if (pAdapterInfo == NULL) {
    LOG(LEVEL_ERROR, "error:malloc(): for GetAdaptersinfo\n");
    return result;
  }

  /* Query the adapter info. If the buffer is not big enough, loop around
   * and try again */
again:
  err = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
  if (err == ERROR_BUFFER_OVERFLOW) {
    free(pAdapterInfo);
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc((size_t)ulOutBufLen);
    if (pAdapterInfo == NULL) {
      LOG(LEVEL_ERROR, "error:malloc(): for GetAdaptersinfo\n");
      return result;
    }
    goto again;
  }
  if (err != NO_ERROR) {
    LOG(LEVEL_ERROR, "GetAdaptersInfo failed with error: %u\n", (unsigned)err);
    return result;
  }

  /* loop through all adapters looking for ours */
  for (pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next) {
    if (rawsock_is_adapter_names_equal(pAdapter->AdapterName, ifname))
      break;
  }

  if (pAdapter) {
    const IP_ADDR_STRING *addr;
    for (addr = &pAdapter->IpAddressList; addr; addr = addr->Next) {
      ipv4address_t x;
      massip_parse_ipv4(&x, addr->IpAddress.String);
      if (x != 0xFFFFFFFF) {
        *result = x;
        goto end;
      }
    }
  }

end:
  if (pAdapterInfo)
    free(pAdapterInfo);

  return result;
}
/*****************************************************************************
 *****************************************************************************/
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || 1
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef AF_LINK
#include <net/if_dl.h>
#endif
#ifdef AF_PACKET
#include <netpacket/packet.h>
#endif

ipv4address_t *rawsock_get_adapter_ip(ipv4address_t *result,
                                      const char *ifname) {
  int err;
  struct ifaddrs *ifap;
  struct ifaddrs *p;

  *result = 0;

  /* Get the list of all network adapters */
  err = getifaddrs(&ifap);
  if (err != 0) {
    LOG(LEVEL_ERROR, "getifaddrs: %s\n", strerror(errno));
    return result;
  }

  /* Look through the list until we get our adapter */
  for (p = ifap; p; p = p->ifa_next) {
    if (strcmp(ifname, p->ifa_name) == 0 && p->ifa_addr &&
        p->ifa_addr->sa_family == AF_INET)
      break;
  }
  if (p == NULL)
    goto error; /* not found */

  /* Return the address */
  {
    struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;

    *result = ntohl(sin->sin_addr.s_addr);
  }

  freeifaddrs(ifap);
  return result;
error:
  freeifaddrs(ifap);
  return result;
}

#endif
