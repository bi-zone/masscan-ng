/*
    portable interface to "raw sockets"

    This uses both "libpcap" on systems, but on Linux, we try to use the
    basic raw sockets, bypassing libpcap for better performance.
*/
#include "rawsock.h"
#include "logger.h"
#include "main-globals.h"
#include "main-ptrace.h"
#include "pixie-timer.h"
#include "proto-preprocess.h"
#include "stack-arpv4.h"
#include "stack-ndpv6.h"
#include "string_s.h"
#include "stub-pcap.h"
#include "stub-pfring.h"
#include "templ-pkt.h"
#include "util-cross.h"
#include "util-malloc.h"

#include <assert.h>
#include <ctype.h>

static int is_pcap_file = 0;

#ifdef WIN32
// clang-format off
#include <winsock.h>
#include <iphlpapi.h>
// clang-format on

#if defined(_MSC_VER)
#pragma comment(lib, "IPHLPAPI.lib")
#endif

#elif defined(__GNUC__)
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#else
#endif

#include "rawsock-adapter.h"

#define SENDQ_SIZE (65536 * 8)

struct AdapterNames {
  char *easy_name;
  char *hard_name;
};

struct AdapterNames adapter_names[64];
unsigned adapter_name_count = 0;

/***************************************************************************
 ***************************************************************************/
#ifdef WIN32
int pcap_setdirection(pcap_t *pcap, pcap_direction_t direction) {
  static int (*real_setdirection)(pcap_t *, pcap_direction_t) = 0;

  if (real_setdirection == 0) {
    void *h = LoadLibraryA("wpcap.dll");
    if (h == NULL) {
      LOG(LEVEL_ERROR, "couldn't load wpcap.dll: %u\n",
          (unsigned)GetLastError());
      return -1;
    }

    real_setdirection = (int (*)(pcap_t *, pcap_direction_t))GetProcAddress(
        h, "pcap_setdirection");
    if (real_setdirection == 0) {
      LOG(LEVEL_ERROR, "couldn't find pcap_setdirection(): %u\n",
          (unsigned)GetLastError());
      return -1;
    }
  }

  return real_setdirection(pcap, direction);
}
#endif

/***************************************************************************
 ***************************************************************************/
void rawsock_init(void) {
#ifdef WIN32
  /* Declare and initialize variables */

  // It is possible for an adapter to have multiple
  // IPv4 addresses, gateways, and secondary WINS servers
  // assigned to the adapter.
  //
  // Note that this sample code only prints out the
  // first entry for the IP address/mask, and gateway, and
  // the primary and secondary WINS server for each adapter.

  PIP_ADAPTER_INFO pAdapterInfo;
  PIP_ADAPTER_INFO pAdapter = NULL;
  DWORD dwRetVal = 0;
  size_t i;

  /* variables used to print DHCP time info */
  // struct tm newtime;
  // char buffer[32];
  // errno_t error;

  ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
  pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
  if (pAdapterInfo == NULL) {
    LOG(LEVEL_WARNING,
        "Error allocating memory needed to call GetAdaptersinfo\n");
    return;
  }
  // Make an initial call to GetAdaptersInfo to get
  // the necessary size into the ulOutBufLen variable
  if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
    free(pAdapterInfo);
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc((size_t)ulOutBufLen);
    if (pAdapterInfo == NULL) {
      LOG(LEVEL_WARNING,
          "Error allocating memory needed to call GetAdaptersinfo\n");
      return;
    }
  }

  if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
    for (pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next) {
      if (pAdapter->Type != MIB_IF_TYPE_ETHERNET)
        continue;

      {
        size_t name_len = strlen(pAdapter->AdapterName) + 12 + 1;
        char *name = (char *)malloc(name_len);
        size_t addr_len = (size_t)pAdapter->AddressLength * 3 + 1;
        char *addr = (char *)malloc(addr_len);

        if (name == NULL || addr == NULL)
          exit(1);

        sprintf_s(name, name_len, "\\Device\\NPF_%s", pAdapter->AdapterName);

        for (i = 0; i < (size_t)pAdapter->AddressLength; i++) {
          size_t offset = i * 3;
          if (i == (size_t)(pAdapter->AddressLength - 1))
            sprintf_s(addr + offset, addr_len - offset, "%.2X",
                      pAdapter->Address[i]);
          else
            sprintf_s(addr + offset, addr_len - offset, "%.2X-",
                      pAdapter->Address[i]);
        }
        adapter_names[adapter_name_count].easy_name = addr;
        adapter_names[adapter_name_count].hard_name = name;
        adapter_name_count++;
      }

      {
        size_t name_len = strlen(pAdapter->AdapterName) + 12 + 1;
        char *name = (char *)malloc(name_len);
        size_t addr_len = strlen(pAdapter->IpAddressList.IpAddress.String) + 1;
        char *addr = (char *)malloc(addr_len);
        if (name == NULL || addr == NULL)
          exit(1);
        sprintf_s(name, name_len, "\\Device\\NPF_%s", pAdapter->AdapterName);
        sprintf_s(addr, addr_len, "%s",
                  pAdapter->IpAddressList.IpAddress.String);
        adapter_names[adapter_name_count].easy_name = addr;
        adapter_names[adapter_name_count].hard_name = name;
        adapter_name_count++;
      }
    }
  } else {
    LOG(LEVEL_WARNING, "GetAdaptersInfo failed with error: %u\n",
        (unsigned)dwRetVal);
  }

  free(pAdapterInfo);
#else
  PFRING_init();
#endif
  return;
}

/***************************************************************************
 * This function prints to the command line a list of all the network
 * interfaces/devices.
 ***************************************************************************/
void rawsock_list_adapters(void) {
  pcap_if_t *alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (PCAP.findalldevs(&alldevs, errbuf) != -1) {
    int i;
    const pcap_if_t *d;
    i = 0;

    if (alldevs == NULL) {
      LOG(LEVEL_WARNING,
          "ERR:libpcap: no adapters found, are you sure you are root?\n");
    }
    /* Print the list */
    for (d = alldevs; d; d = PCAP.dev_next(d)) {
      LOG(LEVEL_ERROR, " %d  %s \t", i++, PCAP.dev_name(d));
      if (PCAP.dev_description(d))
        LOG(LEVEL_ERROR, "(%s)\n", PCAP.dev_description(d));
      else
        LOG(LEVEL_ERROR, "(No description available)\n");
    }
    LOG(LEVEL_ERROR, "\n");
    PCAP.freealldevs(alldevs);
  } else {
    LOG(LEVEL_ERROR, "%s\n", errbuf);
  }
}

/***************************************************************************
 ***************************************************************************/
static const char *adapter_from_index(unsigned index) {
  pcap_if_t *alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];
  int x;

  x = PCAP.findalldevs(&alldevs, errbuf);
  if (x != -1) {
    const pcap_if_t *d;

    if (alldevs == NULL) {
      LOG(LEVEL_WARNING,
          "ERR:libpcap: no adapters found, are you sure you are root?\n");
    }
    /* Print the list */
    for (d = alldevs; d; d = PCAP.dev_next(d)) {
      if (index-- == 0)
        return PCAP.dev_name(d);
    }
    return 0;
  } else {
    return 0;
  }
}

/***************************************************************************
 * Some methods of transmit queue multiple packets in a buffer then
 * send all queued packets at once. At the end of a scan, we might have
 * some pending packets that haven't been transmitted yet. Therefore,
 * we'll have to flush them.
 ***************************************************************************/
void rawsock_flush(struct Adapter *adapter) {

  if (adapter->sendq) {
    PCAP.sendqueue_transmit(adapter->pcap, adapter->sendq, 0);

    /* Dude, I totally forget why this step is necessary. I vaguely
     * remember there's a good reason for it though */
    PCAP.sendqueue_destroy(adapter->sendq);
    adapter->sendq = PCAP.sendqueue_alloc(SENDQ_SIZE);
  }
}

/***************************************************************************
 * wrapper for libpcap's sendpacket
 *
 * PORTABILITY: WINDOWS and PF_RING
 * For performance, Windows and PF_RING can queue up multiple packets, then
 * transmit them all in a chunk. If we stop and wait for a bit, we need
 * to flush the queue to force packets to be transmitted immediately.
 ***************************************************************************/
int rawsock_send_packet(struct Adapter *adapter, unsigned char *packet,
                        unsigned length, unsigned flush) {
  /* Why: this happens in "offline mode", when we are benchmarking the
   * core algorithms without sending packets. */
  if (adapter == 0) {
    return 0;
  }

  /* Print --packet-trace if debugging */
  if (adapter->is_packet_trace) {
    packet_trace(stdout, adapter->pt_start, packet, (size_t)length, 1);
  }

  /* PF_RING */
  if (adapter->ring) {
    int err = PF_RING_ERROR_NO_TX_SLOT_AVAILABLE;

    while (err == PF_RING_ERROR_NO_TX_SLOT_AVAILABLE) {
      err = PFRING.send(adapter->ring, packet, length, (unsigned char)flush);
    }
    if (err < 0) {
      LOG(LEVEL_INFO, "pfring:xmit: ERROR %d\n", err);
    }
    return err;
  }

  /* WINDOWS PCAP */
  if (adapter->sendq) {
    int err;
    struct pcap_pkthdr hdr;
    hdr.len = length;
    hdr.caplen = length;

    err = PCAP.sendqueue_queue(adapter->sendq, &hdr, packet);
    if (err) {
      rawsock_flush(adapter);
      PCAP.sendqueue_queue(adapter->sendq, &hdr, packet);
    }

    if (flush) {
      rawsock_flush(adapter);
    }

    return 0;
  }

  /* LIBPCAP */
  if (adapter->pcap) {
    int err;
    err = PCAP.sendpacket(adapter->pcap, packet, length);
    if (err == -1) {
      PCAP.perror(adapter->pcap, "PCAP.perror(sendpacket) - ");
    }
    return err;
  }

  return 0;
}

/***************************************************************************
 ***************************************************************************/
int rawsock_recv_packet(struct Adapter *adapter, unsigned *length,
                        unsigned *secs, unsigned *usecs,
                        unsigned char **packet) {

  if (adapter->ring) {
    /* This is for doing libpfring instead of libpcap */
    struct pfring_pkthdr hdr;
    int err;

  again_ring:
    err = PFRING.recv(adapter->ring, packet, 0, /* zero-copy */
                      &hdr, 0                   /* return immediately */
    );
    if (err == PF_RING_ERROR_NO_PKT_AVAILABLE || hdr.caplen == 0) {
      PFRING.poll(adapter->ring, 1);
      if (is_tx_done)
        return 1;
      goto again_ring;
    }
    if (err) {
      LOG(LEVEL_WARNING, "PFRING.recv ERROR %d\n", err);
      return 1;
    }

    *length = hdr.caplen;
    *secs = (unsigned)hdr.ts.tv_sec;
    *usecs = (unsigned)hdr.ts.tv_usec;

  } else if (adapter->pcap) {
    struct pcap_pkthdr *hdr;
    int err;

  again_pcap_next_ex:
    err = PCAP.next_ex(adapter->pcap, &hdr, packet);
    if (err == 0) {
      if (is_tx_done)
        return 1;
      goto again_pcap_next_ex;
    }
    if (err != 1) {
      if (is_pcap_file) {
        // pixie_time_set_offset(10*100000);
        is_tx_done = 1;
        is_rx_done = 1;
      }
      LOG(LEVEL_WARNING, "PCAP.next_ex ERROR %d\n", err);
      if (err == -1) {
        PCAP.perror(adapter->pcap, "PCAP.perror(next_ex) - ");
      }
      return 1;
    }

    *length = hdr->caplen;
    *secs = (unsigned)hdr->ts.tv_sec;
    *usecs = (unsigned)hdr->ts.tv_usec;
  } /* else if (adapter->pcap) {
      struct pcap_pkthdr hdr;

      *packet = PCAP.next(adapter->pcap, &hdr);

      if (*packet == NULL) {
          if (is_pcap_file) {
              //pixie_time_set_offset(10*100000);
              is_tx_done = 1;
              is_rx_done = 1;
          }
          return 1;
      }

      *length = hdr.caplen;
      *secs = (unsigned)hdr.ts.tv_sec;
      *usecs = (unsigned)hdr.ts.tv_usec;
  } */

  return 0;
}

/***************************************************************************
 * Sends the TCP SYN probe packet.
 *
 * Step 1: format the packet
 * Step 2: send it in a portable manner
 ***************************************************************************/

void rawsock_send_probe_ipv4(struct Adapter *adapter,
                             const ipv4address_t *ip_them, unsigned port_them,
                             const ipv4address_t *ip_me, unsigned port_me,
                             unsigned seqno, unsigned flush,
                             struct TemplateSet *tmplset) {

  unsigned char px[2048];
  size_t packet_length;

  /*
   * Construct the destination packet
   */
  template_set_target_ipv4(tmplset, ip_them, port_them, ip_me, port_me, seqno,
                           px, sizeof(px), &packet_length);

  /*
   * Send it
   */
  rawsock_send_packet(adapter, px, (unsigned)packet_length, flush);
}

void rawsock_send_probe_ipv6(struct Adapter *adapter,
                             const ipv6address_t *ip_them, unsigned port_them,
                             const ipv6address_t *ip_me, unsigned port_me,
                             unsigned seqno, unsigned flush,
                             struct TemplateSet *tmplset) {

  unsigned char px[2048];
  size_t packet_length;

  /* Construct the destination packet */
  template_set_target_ipv6(tmplset, ip_them, port_them, ip_me, port_me, seqno,
                           px, sizeof(px), &packet_length);

  /* Send it */
  rawsock_send_packet(adapter, px, (unsigned)packet_length, flush);
}

/***************************************************************************
 * Used on Windows: network adapters have horrible names, so therefore we
 * use numeric indexes instead. You can which adapter you are looking for
 * by typing "--iflist" as an option.
 ***************************************************************************/
static int is_numeric_index(const char *ifname) {
  int result = 1;
  size_t i;

  /* empty strings aren't numbers */
  if (ifname[0] == '\0')
    return 0;

  /* 'true' if all digits */
  for (i = 0; ifname[i]; i++) {
    char c = ifname[i];

    if (c < '0' || '9' < c)
      result = 0;
  }

  return result;
}

/***************************************************************************
 * Used on Windows: if the adapter name is a numeric index, convert it to
 * the full name.
 ***************************************************************************/
const char *rawsock_win_name(const char *ifname) {
  if (is_numeric_index(ifname)) {
    const char *new_adapter_name;

    new_adapter_name = adapter_from_index(atoi(ifname));
    if (new_adapter_name)
      return new_adapter_name;
  }

  return ifname;
}

/***************************************************************************
 * Configure the socket to not capture transmitted packets. This is needed
 * because we transmit packets at a rate of millions per second, which will
 * overwhelm the receive thread.
 *
 * PORTABILITY: Windows doesn't seem to support this feature, so instead
 * what we do is apply a BPF filter to ignore the transmits, so that they
 * still get filtered at a low level.
 ***************************************************************************/
void rawsock_ignore_transmits(struct Adapter *adapter, const char *ifname) {

  if (adapter->ring) {
    /* PORTABILITY: don't do anything for PF_RING, because it's
     * actually done when we create the adapter, because we can't
     * reconfigure the adapter after it's been activated. */
    return;
  }

  if (adapter->pcap) {
    int err;
    err = PCAP.setdirection(adapter->pcap, PCAP_D_IN);
    if (err) {
      ; // PCAP.perror(adapter->pcap, "if: pcap_setdirection(IN)");
    } else {
      LOG(LEVEL_DEBUG, "if:%s: not receiving transmits\n", ifname);
    }
  }
}

/***************************************************************************
 ***************************************************************************/
void rawsock_close_adapter(struct Adapter *adapter) {
  if (adapter->ring) {
    PFRING.close(adapter->ring);
  }
  if (adapter->pcap) {
    PCAP.close(adapter->pcap);
  }
  if (adapter->sendq) {
    PCAP.sendqueue_destroy(adapter->sendq);
  }

  free(adapter);
}

/***************************************************************************
 * Does the name look like a PF_RING DNA adapter? Common names are:
 * dna0
 * dna1
 * dna0@1
 *
 ***************************************************************************/
static int is_pfring_dna(const char *name) {
  if (strlen(name) < 4)
    return 0;
  if (memcmp(name, "zc:", 3) == 0)
    return 1;
  if (memcmp(name, "dna", 3) != 0)
    return 0;

  name += 3;

  if (!isdigit(name[0] & 0xFF))
    return 0;
  while (isdigit(name[0] & 0xFF))
    name++;

  if (name[0] == '\0')
    return 1;

  if (name[0] != '@')
    return 0;
  else
    name++;

  if (!isdigit(name[0] & 0xFF))
    return 0;
  while (isdigit(name[0] & 0xFF))
    name++;

  if (name[0] == '\0')
    return 1;
  else
    return 0;
}

/***************************************************************************
 ***************************************************************************/
struct Adapter *rawsock_init_adapter(const char *adapter_name,
                                     unsigned is_pfring, unsigned is_sendq,
                                     unsigned is_packet_trace,
                                     unsigned is_offline,
                                     const char *bpf_filter, unsigned is_vlan,
                                     unsigned vlan_id) {

  struct Adapter *adapter;
  char errbuf[PCAP_ERRBUF_SIZE] = "pcap";

  /* BPF filter not supported on some platforms, so ignore this compiler
   * warning when unused */
  UNUSEDPARM(bpf_filter);

  adapter = CALLOC(1, sizeof(*adapter));
  adapter->is_packet_trace = is_packet_trace;
  adapter->pt_start = 1.0 * pixie_gettime() / 1000000.0;

  adapter->is_vlan = is_vlan;
  adapter->vlan_id = vlan_id;

  if (is_offline) {
    return adapter;
  }

  /*----------------------------------------------------------------
   * PORTABILITY: WINDOWS
   * If is all digits index, then look in indexed list
   *----------------------------------------------------------------*/
  if (is_numeric_index(adapter_name)) {
    const char *new_adapter_name;

    new_adapter_name = adapter_from_index(atoi(adapter_name));
    if (new_adapter_name == NULL) {
      LOG(LEVEL_ERROR, "pcap_open_live(%s) error: bad index\n", adapter_name);
      rawsock_close_adapter(adapter);
      return NULL;
    } else
      adapter_name = new_adapter_name;
  }

  /*----------------------------------------------------------------
   * PORTABILITY: PF_RING
   *  If we've been told to use --pfring, then attempt to open the
   *  network adapter using the PF_RING API rather than libpcap.
   *  Since a lot of things can go wrong, we do a lot of extra
   *  logging here.
   *----------------------------------------------------------------*/
  if (is_pfring &&
      !is_pfring_dna(
          adapter_name)) { /*First ensure pfring dna adapter is available*/
    LOG(LEVEL_ERROR, "No pfring adapter available. Please install pfring or "
                     "run masscan without the --pfring option.\n");
    rawsock_close_adapter(adapter);
    return NULL;
  }

  if (is_pfring_dna(adapter_name)) {
    int err;
    unsigned version;

    /*
     * Open
     *
     * TODO: Do we need the PF_RING_REENTRANT flag? We only have one
     * transmit and one receive thread, so I don't think we need it.
     * Also, this reduces performance in half, from 12-mpps to
     * 6-mpps.
     * NOTE: I don't think it needs the "re-entrant" flag, because it
     * transmit and receive are separate functions?
     */
    LOG(LEVEL_DEBUG, "pfring:'%s': opening...\n", adapter_name);
    adapter->ring = PFRING.open(adapter_name, 1500, 0); // PF_RING_REENTRANT);
    adapter->pcap = (pcap_t *)adapter->ring;
    adapter->link_type = 1;
    if (adapter->ring == NULL) {
      LOG(LEVEL_ERROR, "pfring:'%s': OPEN ERROR: %s\n", adapter_name,
          strerror(errno));
      rawsock_close_adapter(adapter);
      return NULL;
    } else
      LOG(LEVEL_INFO, "pfring:'%s': successfully opened\n", adapter_name);

    /*
     * Housekeeping
     */
    PFRING.set_application_name(adapter->ring, "masscan");
    PFRING.version(adapter->ring, &version);
    LOG(LEVEL_INFO, "pfring: version %d.%d.%d\n", (version >> 16) & 0xFFFF,
        (version >> 8) & 0xFF, (version >> 0) & 0xFF);

    LOG(LEVEL_DEBUG, "pfring:'%s': setting direction\n", adapter_name);
    err = PFRING.set_direction(adapter->ring, rx_only_direction);
    if (err) {
      LOG(LEVEL_ERROR, "pfring:'%s': setdirection = %d\n", adapter_name, err);
    } else
      LOG(LEVEL_DEBUG, "pfring:'%s': direction success\n", adapter_name);

    /*
     * Activate
     *
     * PF_RING requires a separate activation step.
     */
    LOG(LEVEL_DEBUG, "pfring:'%s': activating\n", adapter_name);
    err = PFRING.enable_ring(adapter->ring);
    if (err != 0) {
      LOG(LEVEL_ERROR, "pfring: '%s': ENABLE ERROR: %s\n", adapter_name,
          strerror(errno));
      rawsock_close_adapter(adapter);
      return NULL;
    } else
      LOG(LEVEL_INFO, "pfring:'%s': successfully enabled\n", adapter_name);

    return adapter;
  }

  /*----------------------------------------------------------------
   * Kludge: for using files
   *----------------------------------------------------------------*/
  if (memcmp(adapter_name, "file:", 5) == 0) {
    LOG(LEVEL_INFO, "pcap: file: %s\n", adapter_name + 5);
    is_pcap_file = 1;

    adapter->pcap = PCAP.open_offline(adapter_name + 5, errbuf);
    if (adapter->pcap == NULL) {
      LOG(LEVEL_ERROR, "FAIL:%s: can't open adapter: %s\n", adapter_name,
          errbuf);
      if (strstr(errbuf, "perm")) {
        LOG(LEVEL_ERROR, "FAIL: permission denied\n");
        LOG(LEVEL_ERROR, " [hint] need to sudo or run as root or something\n");
      }
      rawsock_close_adapter(adapter);
      return NULL;
    }

    adapter->link_type = PCAP.datalink(adapter->pcap);
    switch (adapter->link_type) {
    case -1:
      PCAP.perror(adapter->pcap, "if: datalink");
      rawsock_close_adapter(adapter);
      return NULL;
    case 1:  /* Ethernet */
    case 12: /* IP Raw */
      break;
    default:
      LOG(LEVEL_WARNING, "pcap: unknown data link type: %u(%s)\n",
          adapter->link_type, PCAP.datalink_val_to_name(adapter->link_type));
      break;
    }
    LOG(LEVEL_INFO, "[+] pcap:file:'%s' successfully enabled\n",
        adapter_name + 5);
    return adapter;
  }
  /*----------------------------------------------------------------
   * PORTABILITY: LIBPCAP
   *
   * This is the standard that should work everywhere.
   *----------------------------------------------------------------*/
  {
    int err;
    LOG(LEVEL_INFO, "[+] if(%s): pcap: %s\n", adapter_name, PCAP.lib_version());
    LOG(LEVEL_DEBUG, "[+] if(%s): opening...\n", adapter_name);

    /* This reserves resources, but doesn't actually open the
     * adapter until we call pcap_activate */
    adapter->pcap = PCAP.create(adapter_name, errbuf);
    if (adapter->pcap == NULL) {
      adapter->pcap = PCAP.open_live(adapter_name, /* interface name */
                                     65536,        /* max packet size */
                                     8,            /* promiscuous mode */
                                     1000, /* read timeout in milliseconds */
                                     errbuf);
      if (adapter->pcap == NULL) {
        LOG(LEVEL_ERROR, "FAIL:%s: can't open adapter: %s\n", adapter_name,
            errbuf);
        if (strstr(errbuf, "perm")) {
          LOG(LEVEL_ERROR, "FAIL: permission denied\n");
          LOG(LEVEL_ERROR,
              " [hint] need to sudo or run as root or something\n");
        }
        rawsock_close_adapter(adapter);
        return NULL;
      }
    } else {
      err = PCAP.set_snaplen(adapter->pcap, 65536);
      if (err) {
        PCAP.perror(adapter->pcap, "if: set_snaplen");
        goto pcap_error;
      }

      err = PCAP.set_promisc(adapter->pcap, 8);
      if (err) {
        PCAP.perror(adapter->pcap, "if: set_promisc");
        goto pcap_error;
      }

      err = PCAP.set_timeout(adapter->pcap, 1000);
      if (err) {
        PCAP.perror(adapter->pcap, "if: set_timeout");
        goto pcap_error;
      }

      err = PCAP.set_immediate_mode(adapter->pcap, 1);
      if (err) {
        PCAP.perror(adapter->pcap, "if: set_immediate_mode");
        goto pcap_error;
      }

      /* If errors happen, they aren't likely to happen above, but will
       * happen where when they are applied */
      err = PCAP.activate(adapter->pcap);
      switch (err) {
      case 0:
        /* drop down below */
        break;
      case PCAP_ERROR_PERM_DENIED:
        LOG(LEVEL_ERROR, "[-] FAIL: permission denied\n");
        LOG(LEVEL_ERROR,
            "    [hint] need to sudo or run as root or something\n");
        goto pcap_error;
      default:
        LOG(LEVEL_ERROR, "[-] if(%s): activate:%d: %s\n", adapter_name, err,
            PCAP.geterr(adapter->pcap));
        if (err < 0)
          goto pcap_error;
      }
    }
    LOG(LEVEL_INFO, "[+] if(%s): successfully opened\n", adapter_name);

    /* Figure out the link-type. We suport Ethernet and IP */
    adapter->link_type = PCAP.datalink(adapter->pcap);
    switch (adapter->link_type) {
    case -1:
      PCAP.perror(adapter->pcap, "if: datalink");
      goto pcap_error;
    case 0: /* Null/Loopback [VPN tunnel] */
      LOG(LEVEL_WARNING, "[+] if(%s): VPN tunnel interface found\n",
          adapter_name);
      break;
    case 1:  /* Ethernet */
    case 12: /* IP Raw */
      break;
    default:
      LOG(LEVEL_WARNING, "[-] if(%s): unknown data link type: %u(%s)\n",
          adapter_name, adapter->link_type,
          PCAP.datalink_val_to_name(adapter->link_type));
      break;
    }
    LOG(LEVEL_INFO, "[+] pcap:if:'%s': successfully enabled\n", adapter_name);
  }

  /*----------------------------------------------------------------
   * PORTABILITY: WINDOWS
   *
   * The transmit rate on Windows is really slow, like 40-kpps.
   * The speed can be increased by using the "sendqueue" feature
   * to roughly 300-kpps.
   *----------------------------------------------------------------*/
  adapter->sendq = 0;

#if defined(WIN32)
  if (is_sendq) {
    adapter->sendq = PCAP.sendqueue_alloc(SENDQ_SIZE);
  }
#endif

  return adapter;

pcap_error:
  if (strcmp(adapter_name, "vmnet1") == 0) {
    LOG(LEVEL_ERROR, " [hint] VMware on Macintosh doesn't support masscan\n");
  }
  rawsock_close_adapter(adapter);
  return NULL;
}

/***************************************************************************
 * for testing when two Windows adapters have the same name. Sometimes
 * the \Device\NPF_ string is prepended, sometimes not.
 ***************************************************************************/
int rawsock_is_adapter_names_equal(const char *lhs, const char *rhs) {
  if (memcmp(lhs, "\\Device\\NPF_", 12) == 0) {
    lhs += 12;
  }
  if (memcmp(rhs, "\\Device\\NPF_", 12) == 0) {
    rhs += 12;
  }
  return strcmp(lhs, rhs) == 0;
}

/***************************************************************************
 * Runs some tests when the "--debug if" option is given on the
 * command-line. This is useful to figure out why the interface you
 * are accessing doesn't work.
 ***************************************************************************/
int rawsock_selftest_if(const char *ifname) {
  int err;
  ipv4address_t ipv4;
  ipv6address_t ipv6;
  ipv4address_t router_ipv4 = 0;
  macaddress_t source_mac = {{0, 0, 0, 0, 0, 0}};
  struct Adapter *adapter;
  char ifname2[246];
  ipaddress_formatted_t fmt;

  /* Get the interface */
  if (ifname == NULL || ifname[0] == 0) {
    err = rawsock_get_default_interface(ifname2, sizeof(ifname2));
    if (err) {
      LOG(LEVEL_WARNING, "[-] if = not found (err=%d)\n", err);
      return -1;
    }
    ifname = ifname2;
  }
  LOG(LEVEL_WARNING, "[+] if = %s\n", ifname);

  /* Initialize the adapter. */
  adapter = rawsock_init_adapter(ifname, 0, 0, 0, 0, 0, 0, 0);
  if (adapter == 0) {
    LOG(LEVEL_WARNING, "[-] pcap = failed\n");
    return -1;
  } else {
    LOG(LEVEL_WARNING, "[+] pcap = opened\n");
  }

  /* IPv4 address */
  rawsock_get_adapter_ip(&ipv4, ifname);
  if (ipv4 == 0) {
    LOG(LEVEL_WARNING, "get-ip: returned err\n");
    LOG(LEVEL_WARNING, "[-] source-ipv4 = not found (err)\n");
  } else {
    ipv4address_fmt(&fmt, &ipv4);
    LOG(LEVEL_WARNING, "[+] source-ipv4 = %s\n", fmt.string);
  }

  /* IPv6 address */
  rawsock_get_adapter_ipv6(&ipv6, ifname);
  if (ipv6address_is_zero(&ipv6)) {
    LOG(LEVEL_WARNING, "[-] source-ipv6 = not found\n");
  } else {
    ipv6address_fmt(&fmt, &ipv6);
    LOG(LEVEL_WARNING, "[+] source-ipv6 = [%s]\n", fmt.string);
  }

  /* MAC address */
  err =
      rawsock_get_adapter_mac(ifname, source_mac.addr, sizeof(source_mac.addr));
  if (err) {
    LOG(LEVEL_WARNING, "[-] source-mac = not found (err=%d)\n", err);
  } else {
    macaddress_fmt(&fmt, &source_mac);
    LOG(LEVEL_WARNING, "[+] source-mac = %s\n", fmt.string);
  }

  switch (adapter->link_type) {
  case 0:
    LOG(LEVEL_WARNING, "[+] router-ip = implicit\n");
    LOG(LEVEL_WARNING, "[+] router-mac = implicit\n");
    break;
  default:
    /* IPv4 router IP address */
    err = rawsock_get_default_gateway(ifname, &router_ipv4);
    if (err) {
      LOG(LEVEL_WARNING, "[-] router-ip = not found(err=%d)\n", err);
    } else {
      ipv4address_fmt(&fmt, &router_ipv4);
      LOG(LEVEL_WARNING, "[+] router-ip = %s\n", fmt.string);
    }

    /* IPv4 router MAC address */
    {
      macaddress_t router_mac = {{0, 0, 0, 0, 0, 0}};
      stack_arp_resolve(adapter, &ipv4, &source_mac, &router_ipv4, &router_mac);

      if (macaddress_is_zero(&router_mac)) {
        LOG(LEVEL_WARNING, "[-] router-mac-ipv4 = not found\n");
      } else {
        macaddress_fmt(&fmt, &router_mac);
        LOG(LEVEL_WARNING, "[+] router-mac-ipv4 = %s\n", fmt.string);
      }
    }

    /* IPv6 router MAC address.
     * If it's not configured, then we need to send a (synchronous) query
     * to the network in order to discover the location of routers on
     * the local network */
    if (!ipv6address_is_zero(&ipv6)) {
      macaddress_t router_mac = {{0, 0, 0, 0, 0, 0}};

      stack_ndpv6_resolve(adapter, &ipv6, &source_mac, &router_mac);

      if (macaddress_is_zero(&router_mac)) {
        LOG(LEVEL_WARNING, "[-] router-mac-ipv6 = not found\n");
      } else {
        macaddress_fmt(&fmt, &router_mac);
        LOG(LEVEL_WARNING, "[+] router-mac-ipv6 = %s\n", fmt.string);
      }
    }
  }

  rawsock_close_adapter(adapter);
  return 0;
}

/***************************************************************************
 ***************************************************************************/
int rawsock_selftest() { return 0; }
