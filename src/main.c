/*

    main

    This includes:

    * main()
    * transmit_thread() - transmits probe packets
    * receive_thread() - receives response packets

    You'll be wanting to study the transmit/receive threads, because that's
    where all the action is.

    This is the lynch-pin of the entire program, so it includes a heckuva lot
    of headers, and the functions have a lot of local variables. I'm trying
    to make this file relative "flat" this way so that everything is visible.
*/

#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(WIN32)
#include <WinSock.h>
#if defined(_MSC_VER)
#pragma comment(lib, "Ws2_32.lib")
#endif
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "in-binary.h"    /* convert binary output to XML/JSON */
#include "logger.h"       /* adjust with -v command-line opt */
#include "main-globals.h" /* all the global variables in the program */
#include "main-params.h"
#include "main-readrange.h"
#include "main-status.h"   /* printf() regular status updates */
#include "main-throttle.h" /* rate limit */
#include "masscan-version.h"
#include "masscan.h"
#include "massip-parse.h"
#include "massip-port.h"
#include "pixie-backtrace.h"
#include "pixie-threads.h" /* portable threads */
#include "pixie-timer.h"   /* portable time functions */
#include "proto-snmp.h"    /* parse SNMP responses */
#include "proto-x509.h"
#include "rawsock-adapter.h"
#include "rawsock.h" /* API on top of Linux, Windows, Mac OS X*/
#include "receiver.h"
#include "rte-ring.h" /* producer/consumer ring buffer */
#include "scripting.h"
#include "selftest.h"
#include "stack-ndpv6.h"    /* IPv6 Neighbor Discovery Protocol */
#include "stub-pcap.h"      /* dynamically load libpcap library */
#include "syn-cookie.h"     /* for SYN-cookies on send */
#include "templ-payloads.h" /* UDP packet payloads */
#include "templ-pkt.h"      /* packet template, that we use to send */
#include "transmiter.h"
#include "util-checksum.h"
#include "util-cross.h"
#include "util-malloc.h"
#include "util-openssl.h"
#include "util-test.h"
#include "vulncheck.h" /* checking vulns like monlist, poodle, heartblee */

/* yea I know globals suck */
bool volatile is_tx_done = false;
bool volatile is_rx_done = false;
time_t volatile global_now;
uint64_t usec_start;

/***************************************************************************
 * We trap the <ctrl-c> so that instead of exiting immediately, we sit in
 * a loop for a few seconds waiting for any late response. But, the user
 * can press <ctrl-c> a second time to exit that waiting.
 ***************************************************************************/
static void control_c_handler(int x) {
  static bool control_c_pressed = false;
  static bool control_c_pressed_again = false;
  static unsigned count_rx_done = 0;
  UNUSEDPARM(x);

  if (control_c_pressed == false) {
    LOG(LEVEL_WARNING, "waiting several seconds to exit...\n");
    control_c_pressed = true;
    is_tx_done = control_c_pressed;
  } else {
    if (is_rx_done) {
      LOG(LEVEL_ERROR, "\nERROR: threads not exiting %d\n", is_rx_done);
      if (count_rx_done++ > 1) {
        exit(1);
      }
    } else {
      control_c_pressed_again = true;
      is_rx_done = control_c_pressed_again;
      count_rx_done = 1;
    }
  }
}

/***************************************************************************
 * Called from main() to initiate the scan.
 * Launches the 'transmit_thread()' and 'receive_thread()' and waits for
 * them to exit.
 ***************************************************************************/
static int main_scan(struct Masscan *masscan) {

  struct ThreadPair parms_array[8];
  uint64_t count_ips;
  massint128_t tmp;
  uint64_t count_ports;
  uint64_t range;
  size_t index;
  time_t now = time(0);
  struct Status status;
  uint64_t min_index = UINT64_MAX;
  struct MassVulnCheck *vulncheck = NULL;
  struct stack_t *stack;

  memset(parms_array, 0, sizeof(parms_array));

  /* Vuln check initialization */
  if (masscan->vuln_name) {
    size_t i;
    unsigned is_error;
    vulncheck = vulncheck_lookup(masscan->vuln_name);

    /* If no ports specified on command-line, grab default ports */
    is_error = 0;
    if (rangelist_count(&masscan->targets.ports) == 0)
      rangelist_parse_ports(&masscan->targets.ports, vulncheck->ports,
                            &is_error, 0);

    /* Kludge: change normal port range to vulncheck range */
    for (i = 0; i < masscan->targets.ports.count; i++) {
      struct Range *r = &masscan->targets.ports.list[i];
      r->begin = (r->begin & 0xFFFF) | Templ_VulnCheck;
      r->end = (r->end & 0xFFFF) | Templ_VulnCheck;
    }
  }

  /* Initialize the task size */
  count_ips = rangelist_count(&masscan->targets.ipv4) +
              range6list_count(&tmp, &masscan->targets.ipv6)->lo;
  if (count_ips == 0) {
    LOG(LEVEL_ERROR, "FAIL: target IP address list empty\n");
    LOG(LEVEL_ERROR, " [hint] try something like \"--range 10.0.0.0/8\"\n");
    LOG(LEVEL_ERROR,
        " [hint] try something like \"--range 192.168.0.100-192.168.0.200\"\n");
    return 1;
  }
  count_ports = rangelist_count(&masscan->targets.ports);
  if (count_ports == 0) {
    LOG(LEVEL_ERROR, "FAIL: no ports were specified\n");
    LOG(LEVEL_ERROR, " [hint] try something like \"-p80,8000-9000\"\n");
    LOG(LEVEL_ERROR, " [hint] try something like \"--ports 0-65535\"\n");
    return 1;
  }
  range = count_ips * count_ports;
  range += (uint64_t)(masscan->retries * range);

  /* If doing an ARP scan, then don't allow port scanning */
  assert(Templ_ARP == Templ_ARP_last);
  unsigned tmp_templ_arp = Templ_ARP;
  if (rangelist_is_contains(&masscan->targets.ports, &tmp_templ_arp)) {
    if (masscan->targets.ports.count != 1) {
      LOG(LEVEL_ERROR, "FAIL: cannot arpscan and portscan at the same time\n");
      return 1;
    }
  }

  /* If the IP address range is very big, then require that that the
   * user apply an exclude range */
  if (count_ips > 1000000000ULL &&
      rangelist_count(&masscan->exclude.ipv4) == 0) {
    LOG(LEVEL_ERROR, "FAIL: range too big, need confirmation\n");
    LOG(LEVEL_ERROR, " [hint] to prevent accidents, at least one --exclude "
                     "must be specified\n");
    LOG(LEVEL_ERROR,
        " [hint] use \"--exclude 255.255.255.255\" as a simple confirmation\n");
    exit(1);
  }

  /* trim the nmap UDP payloads down to only those ports we are using. This
   * makes lookups faster at high packet rates. */
  payloads_udp_trim(masscan->payloads.udp, &masscan->targets);
  payloads_oproto_trim(masscan->payloads.oproto, &masscan->targets);

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  /* Start scanning threats for each adapter */
  for (index = 0; index < masscan->nic_count; index++) {
    struct ThreadPair *parms = &parms_array[index];
    int err;

    parms->masscan = masscan;
    parms->nic_index = index;
    parms->my_index = masscan->resume.index;
    parms->done_transmitting = 0;
    parms->done_receiving = 0;

    /* needed for --packet-trace option so that we know when we started
     * the scan */
    parms->pt_start = 1.0 * pixie_gettime() / 1000000.0;

    parms->barrier_main_loop = pixie_create_barrier(2);
    if (parms->barrier_main_loop == NULL) {
      LOG(LEVEL_ERROR, "FAIL: failed create barrier\n");
      exit(1);
    }

    /* Turn the adapter on, and get the running configuration */
    err = masscan_initialize_adapter(masscan, index, &parms->source_mac,
                                     &parms->router_mac_ipv4,
                                     &parms->router_mac_ipv6);
    if (err != 0) {
      exit(1);
    }
    parms->adapter = masscan->nic[index].adapter;
    if (!masscan->nic[index].is_usable) {
      LOG(LEVEL_ERROR, "FAIL: failed to detect IP of interface\n");
      LOG(LEVEL_ERROR, " [hint] did you spell the name correctly?\n");
      LOG(LEVEL_ERROR, " [hint] if it has no IP address, "
                       "manually set with \"--adapter-ip 192.168.100.5\"\n");
      exit(1);
    }

    /* Initialize the TCP packet template. The way this works is that
     * we parse an existing TCP packet, and use that as the template for
     * scanning. Then, we adjust the template with additional features,
     * such as the IP address and so on.*/
    parms->tmplset->vulncheck = vulncheck;
    template_packet_init(parms->tmplset, &parms->source_mac,
                         &parms->router_mac_ipv4, &parms->router_mac_ipv6,
                         masscan->payloads.udp, masscan->payloads.oproto,
                         stack_if_datalink(masscan->nic[index].adapter),
                         masscan->seed);

    /* Set the "source port" of everything we transmit. */
    if (masscan->nic[index].src.port.range == 0) {
      unsigned port = 40000 + now % 20000;
      masscan->nic[index].src.port.first = port;
      masscan->nic[index].src.port.last = port;
      masscan->nic[index].src.port.range = 1;
    }

    stack = stack_create(parms->source_mac, &masscan->nic[index].src,
                         masscan->recv_handle_thread_count);
    parms->stack = stack;

    /* Set the "TTL" (IP time-to-live) of everything we send. */
    if (masscan->nmap.ttl)
      template_set_ttl(parms->tmplset, masscan->nmap.ttl);

    if (masscan->nic[0].is_vlan)
      template_set_vlan(parms->tmplset, masscan->nic[0].vlan_id);

    /* trap <ctrl-c> to pause */
    signal(SIGINT, control_c_handler);
  }

  /* Print helpful text */
  {
    char buffer[80];
    struct tm x;

    now = time(0);
    gmtime_s(&x, &now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S GMT", &x);
    LOG(LEVEL_ERROR,
        "Starting " MASSCAN_NAME " " MASSCAN_VERSION " (" MASSCAN_REPO_LINK
        ") at %s\n",
        buffer);

    if (count_ports == 1 &&
        masscan->targets.ports.list->begin == Templ_ICMP_echo &&
        masscan->targets.ports.list->end == Templ_ICMP_echo) { /* ICMP only */
      // LOG(LEVEL_ERROR, " -- forced options: -sn -n --randomize-hosts -v
      // --send-eth\n");
      LOG(LEVEL_ERROR, "Initiating ICMP Echo Scan\n");
      LOG(LEVEL_ERROR, "Scanning %u hosts\n", (unsigned)count_ips);
    } else { /* This could actually also be a UDP only or mixed UDP/TCP/ICMP
                scan */
      LOG(LEVEL_ERROR,
          " -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth\n");
      LOG(LEVEL_ERROR, "Initiating SYN Stealth Scan\n");
      LOG(LEVEL_ERROR, "Scanning %u hosts [%u port%s/host]\n",
          (unsigned)count_ips, (unsigned)count_ports,
          (count_ports == 1) ? "" : "s");
    }
  }

  /* Start all the threads */
  for (index = 0; index < masscan->nic_count; index++) {
    struct ThreadPair *parms = &parms_array[index];

    /* Start the scanning thread.
     * THIS IS WHERE THE PROGRAM STARTS SPEWING OUT PACKETS AT A HIGH
     * RATE OF SPEED. */
    parms->thread_handle_xmit = pixie_begin_thread(transmit_thread, 0, parms);

    /* Start the MATCHING receive thread. Transmit and receive threads
     * come in matching pairs. */
    parms->thread_handle_recv = pixie_begin_thread(receive_thread, 0, parms);
  }

  /* Now wait for <ctrl-c> to be pressed OR for threads to exit */
  pixie_usleep(1000 * 100);
  LOG(LEVEL_INFO, "[+] waiting for threads to finish\n");
  status_start(&status);
  status.is_infinite = masscan->is_infinite;
  while (!is_tx_done && masscan->output.is_status_updates) {
    size_t i;
    double rate = 0;
    uint64_t total_tcbs = 0;
    uint64_t total_synacks = 0;
    uint64_t total_syns = 0;
    uint64_t transmit_queue_count = 0;
    uint64_t recv_queue_count = 0;
    uint64_t timeout_handle_recv = 0;

    /* Find the minimum index of all the threads */
    min_index = UINT64_MAX;
    for (i = 0; i < masscan->nic_count; i++) {
      struct ThreadPair *parms = &parms_array[i];
      uint64_t timeout_handle_recv_tmp;

      if (min_index > parms->my_index)
        min_index = parms->my_index;

      rate += parms->throttler->current_rate;

      if (parms->total_tcbs) {
        total_tcbs += parms->total_tcbs;
      }
      if (parms->total_synacks) {
        total_synacks += parms->total_synacks;
      }
      if (parms->total_syns) {
        total_syns += parms->total_syns;
      }
      transmit_queue_count += rte_ring_count(parms->stack->transmit_queue);
      recv_queue_count += stack_recv_queue_count(parms->stack);
      timeout_handle_recv_tmp =
          (parms->secs_last_recv * 1000 + parms->usecs_last_recv / 1000) -
          (parms->secs_current_recv * 1000 + parms->usecs_current_recv / 1000);
      timeout_handle_recv = max(timeout_handle_recv, timeout_handle_recv_tmp);
    }

    if (min_index >= range && !masscan->is_infinite) {
      /* Note: This is how we can tell the scan has ended */
      is_tx_done = 1;
    }

    /* update screen about once per second with statistics,
     * namely packets/second. */
    status_print(&status, min_index, range, rate, total_tcbs, total_synacks,
                 total_syns, transmit_queue_count, recv_queue_count,
                 timeout_handle_recv, 0,
                 (bool)masscan->output.is_status_ndjson);

    /* Sleep for almost a second */
    pixie_mssleep(750);
  }

  /* If we haven't completed the scan, then save the resume
   * information. */
  if (min_index < count_ips * count_ports) {
    masscan->resume.index = min_index;

    /* Write current settings to "paused.conf" so that the scan can be restarted
     */
    masscan_save_state(masscan);
  }

  /* Now wait for all threads to exit */
  now = time(0);
  for (;;) {
    uint64_t transmit_count = 0;
    uint64_t receive_count = 0;
    size_t i;
    double rate = 0;
    uint64_t total_tcbs = 0;
    uint64_t total_synacks = 0;
    uint64_t total_syns = 0;
    uint64_t transmit_queue_count = 0;
    uint64_t recv_queue_count = 0;
    uint64_t timeout_handle_recv = 0;

    /* Find the minimum index of all the threads */
    min_index = UINT64_MAX;
    for (i = 0; i < masscan->nic_count; i++) {
      struct ThreadPair *parms = &parms_array[i];
      uint64_t timeout_handle_recv_tmp = 0;

      if (min_index > parms->my_index)
        min_index = parms->my_index;

      rate += parms->throttler->current_rate;

      if (parms->total_tcbs) {
        total_tcbs += parms->total_tcbs;
      }
      if (parms->total_synacks) {
        total_synacks += parms->total_synacks;
      }
      if (parms->total_syns) {
        total_syns += parms->total_syns;
      }
      transmit_queue_count += rte_ring_count(parms->stack->transmit_queue);
      recv_queue_count += stack_recv_queue_count(parms->stack);
      timeout_handle_recv_tmp =
          (parms->secs_last_recv * 1000 + parms->usecs_last_recv / 1000) -
          (parms->secs_current_recv * 1000 + parms->usecs_current_recv / 1000);
      timeout_handle_recv = max(timeout_handle_recv, timeout_handle_recv_tmp);
    }

    if (time(0) - now >= masscan->wait) {
      is_rx_done = 1;
    }

    if (time(0) - now - 10 > masscan->wait) {
      LOG(LEVEL_ERROR,
          "[-] Passed the wait window but still running, forcing exit...\n");
      exit(0);
    }

    if (masscan->output.is_status_updates) {
      status_print(&status, min_index, range, rate, total_tcbs, total_synacks,
                   total_syns, transmit_queue_count, recv_queue_count,
                   timeout_handle_recv, masscan->wait - (time(0) - now),
                   (bool)masscan->output.is_status_ndjson);

      for (i = 0; i < masscan->nic_count; i++) {
        struct ThreadPair *parms = &parms_array[i];
        transmit_count += parms->done_transmitting;
        receive_count += parms->done_receiving;
      }

      pixie_mssleep(250);

      if (transmit_count < (uint64_t)masscan->nic_count) {
        continue;
      }
      is_tx_done = 1;
      is_rx_done = 1;
      if (receive_count < (uint64_t)masscan->nic_count) {
        continue;
      }
    } else {
      /* [AFL-fuzz]
       * Join the threads, which doesn't allow us to print out
       * status messages, but allows us to exit cleanly without
       * any waiting */
      for (i = 0; i < masscan->nic_count; i++) {
        struct ThreadPair *parms = &parms_array[i];
        bool is_success;

        pixie_thread_join(parms->thread_handle_xmit);
        parms->thread_handle_xmit = 0;
        pixie_thread_join(parms->thread_handle_recv);
        parms->thread_handle_recv = 0;

        is_success = pixie_delete_barrier(parms->barrier_main_loop);
        if (is_success == false) {
          LOG(LEVEL_WARNING, "FAIL: failed delete barrier\n");
        }
        parms->barrier_main_loop = NULL;
      }
      is_tx_done = 1;
      is_rx_done = 1;
    }

    break;
  }

  /* Now cleanup everything */
  status_finish(&status);

  if (!masscan->output.is_status_updates) {
    uint64_t usec_now = pixie_gettime();
    printf("%u milliseconds elapsed\n",
           (unsigned)((usec_now - usec_start) / 1000));
  }

  LOG(LEVEL_INFO, "[+] all threads have exited\n");

  for (index = 0; index < masscan->nic_count; index++) {
    struct ThreadPair *parms = &parms_array[index];
    stack_destroy(parms->stack);
    template_packet_cleanup(parms->tmplset);
    masscan_cleanup_adapter(masscan, index);
    pixie_delete_barrier(parms->barrier_main_loop);
  }

  return 0;
}

/***************************************************************************
 ***************************************************************************/
int main(int argc, char *argv[]) {
  struct Masscan masscan[1] = {{0}};
  massint128_t tmp;
  size_t i;
  int exit_code = 0;
  int res;
  int has_target_addresses = 0;
  int has_target_ports = 0;

  usec_start = pixie_gettime();
#if defined(WIN32)
  {
    WSADATA x;
    WSAStartup(0x101, &x);
  }
#endif

  global_now = time(0);

  /* Set system to report debug information on crash */
  {
    bool is_backtrace = true;
    for (i = 1; i < (size_t)argc; i++) {
      if (strcmp(argv[i], "--nobacktrace") == 0) {
        is_backtrace = false;
      }
    }
    if (is_backtrace) {
      pixie_backtrace_init(argv[0]);
    }
  }

  /* 14 rounds seem to give way better statistical distribution than 4 with a
  very low impact on scan rate */
  masscan->blackrock_rounds = 14;
  masscan->output.is_show_open = 1;      /* default: show syn-ack, not rst */
  masscan->output.is_status_updates = 1; /* default: show status updates */
  masscan->wait = 10;        /* how long to wait for responses when done */
  masscan->max_rate = 100.0; /* max rate = hundred packets-per-second */
  masscan->nic_count = 1;
  masscan->recv_handle_thread_count = 1;
  masscan->shard.one = 1;
  masscan->shard.of = 1;
  masscan->min_packet_size = 60;
  masscan->payloads.udp = payloads_udp_create();
  masscan->payloads.oproto = payloads_oproto_create();
  strcpy_s(masscan->output.rotate.directory,
           sizeof(masscan->output.rotate.directory), ".");
  masscan->is_capture_cert = true;

  /* Pre-parse the command-line */
  if (masscan_conf_contains("--readscan", argc, argv)) {
    masscan->is_readscan = true;
  }

  /* On non-Windows systems, read the defaults from the file in
   * the /etc directory. These defaults will contain things
   * like the output directory, max packet rates, and so on. Most
   * importantly, the master "--excludefile" might be placed here,
   * so that blacklisted ranges won't be scanned, even if the user
   * makes a mistake */
#if !defined(WIN32)
  if (!masscan->is_readscan) {
    if (access("/etc/" MASSCAN_NAME "/" MASSCAN_NAME ".conf", 0) == 0) {
      masscan_read_config_file(masscan,
                               "/etc/" MASSCAN_NAME "/" MASSCAN_NAME ".conf");
    }
  }
#endif

  /* Read in the configuration from the command-line. We are looking for
   * either options or a list of IPv4 address ranges. */
  masscan_command_line(masscan, argc, argv);

  if (masscan->seed == 0) {
    masscan->seed = get_entropy(); /* entropy for randomness */
  }

  /* Load database files like "nmap-payloads" and "nmap-service-probes" */
  masscan_load_database_files(masscan);

  /*Load the scripting engine if needed and run those that were
   * specified. */
  if (masscan->is_scripting) {
    scripting_init(masscan);
  }

  /* We need to do a separate "raw socket" initialization step. This is
   * for Windows and PF_RING. */
  if (pcap_init() != 0) {
    LOG(LEVEL_DEBUG, "libpcap: failed to load\n");
  }
  rawsock_init();

  // OpenSSL
  res = OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
  if (res != 1) {
    LOG(LEVEL_WARNING, "OPENSSL_init_ssl error %d\n", res);
    exit(1);
  }
  init_openssl_ext_obj();

  /* Init some protocol parser data structures */
  snmp_init();
  x509_init();
  spnego_init();

  /* Apply excludes. People ask us not to scan them, so we maintain a list
   * of their ranges, and when doing wide scans, add the exclude list to
   * prevent them from being scanned. */
  has_target_addresses = massip_has_ipv4_targets(&masscan->targets) ||
                         massip_has_ipv6_targets(&masscan->targets);
  has_target_ports = massip_has_target_ports(&masscan->targets);
  massip_apply_excludes(&masscan->targets, &masscan->exclude);
  if (!has_target_ports && masscan->op == Operation_ListScan)
    massip_add_port_string(&masscan->targets, "80", 0);

  /* Optimize target selection so it's a quick binary search instead
   * of walking large memory tables. When we scan the entire Internet
   * our --excludefile will chop up our pristine 0.0.0.0/0 range into
   * hundreds of subranges. This allows us to grab addresses faster. */
  massip_optimize(&masscan->targets);

  /* FIXME: we only support 63-bit scans at the current time.
   * This is big enough for the IPv4 Internet, where scanning
   * for all TCP ports on all IPv4 addresses results in a 48-bit
   * scan, but this isn't big enough even for a single port on
   * an IPv6 subnet (which are 64-bits in size, usually). However,
   * even at millions of packets per second scanning rate, you still
   * can't complete a 64-bit scan in a reasonable amount of time.
   * Nor would you want to attempt the feat, as it would overload
   * the target IPv6 subnet. Since implementing this would be
   * difficult for 32-bit processors, for now, I'm going to stick
   * to a simple 63-bit scan. */
  if (massint128_bitcount(massip_range(&tmp, &masscan->targets)) > 63) {
    LOG(LEVEL_ERROR,
        "[-] FAIL: scan range too large, max is 63-bits, requested is %u "
        "bits\n",
        massint128_bitcount(&tmp));
    LOG(LEVEL_ERROR, "    Hint: scan range is number of IP addresses times "
                     "number of ports\n");
    LOG(LEVEL_ERROR, "    Hint: IPv6 subnet must be at least /66 \n");
    exit(1);
  }

  /* Once we've read in the configuration, do the operation that was
   * specified */
  switch (masscan->op) {
  case Operation_Default:
    /* Print usage info and exit */
    masscan_usage();
    break;

  case Operation_Scan:
    /* THIS IS THE NORMAL THING */
    if (rangelist_count(&masscan->targets.ipv4) == 0 &&
        massint128_is_zero(range6list_count(&tmp, &masscan->targets.ipv6))) {
      /* We check for an empty target list here first, before the excludes,
       * so that we can differentiate error messages after excludes, in case
       * the user specified addresses, but they were removed by excludes. */
      LOG(LEVEL_ERROR, "FAIL: target IP address list empty\n");
      if (has_target_addresses) {
        LOG(LEVEL_ERROR,
            " [hint] all addresses were removed by exclusion ranges\n");
      } else {
        LOG(LEVEL_ERROR, " [hint] try something like \"--range 10.0.0.0/8\"\n");
        LOG(LEVEL_ERROR, " [hint] try something like \"--range "
                         "192.168.0.100-192.168.0.200\"\n");
      }
      exit(1);
    }
    if (rangelist_count(&masscan->targets.ports) == 0) {
      if (has_target_ports) {
        LOG(LEVEL_ERROR,
            " [hint] all ports were removed by exclusion ranges\n");
      } else {
        LOG(LEVEL_ERROR, "FAIL: no ports were specified\n");
        LOG(LEVEL_ERROR, " [hint] try something like \"-p80,8000-9000\"\n");
        LOG(LEVEL_ERROR, " [hint] try something like \"--ports 0-65535\"\n");
      }
      exit(1);
    }
    exit_code = main_scan(masscan);
    break;
  case Operation_ListScan:
    /* Create a randomized list of IP addresses */
    main_listscan(masscan);
    break;

  case Operation_List_Adapters:
    /* List the network adapters we might want to use for scanning */
    rawsock_list_adapters();
    break;

  case Operation_DebugIF:
    for (i = 0; i < masscan->nic_count; i++) {
      rawsock_selftest_if(masscan->nic[i].ifname);
    }
    break;

  case Operation_ReadRange:
    main_readrange(masscan);
    break;

  case Operation_ReadScan: {
    size_t start;
    size_t stop;

    /* find first file */
    for (start = 1; start < (size_t)argc; start++) {
      if (memcmp(argv[start], "--readscan", 10) == 0) {
        start++;
        break;
      }
    }

    /* find last file */
    for (stop = start + 1; stop < (size_t)argc && argv[stop][0] != '-';
         stop++) {
      // pass
    }

    /* read the binary files, and output them again depending upon
     * the output parameters */
    read_binary_scanfile(masscan, start, stop, argv);
  } break;

  case Operation_Benchmark:
    printf("=== benchmarking (%u-bits) ===\n\n", (unsigned)sizeof(void *) * 8);
    benchmark(masscan);
    exit_code = 1;
    break;

  case Operation_Echo:
    masscan_echo(masscan, stdout, false);
    break;

  case Operation_EchoAll:
    masscan_echo(masscan, stdout, true);
    break;

  case Operation_Selftest:
    /* Do a regression test of all the significant units */
    {
      int x = selftest(masscan);
      if (x != 0) {
        /* one of the selftests failed, so return error */
        LOG(LEVEL_ERROR, "regression test: failed :( \n");
        exit_code = 1;
      } else {
        LOG(LEVEL_WARNING, "regression test: success!\n");
        exit_code = 0;
      }
    }
    break;

  case Operation_NmapHelp:
    print_nmap_help();
    break;

  case Operation_Version:
    print_version();
    break;
  }

  // cleanup
  massip_free(&masscan->targets);
  massip_free(&masscan->exclude);

  masscan_clenup_params(masscan);

  if (masscan->payloads.oproto) {
    payloads_udp_destroy(masscan->payloads.oproto);
    masscan->payloads.oproto = NULL;
  }
  if (masscan->payloads.udp) {
    payloads_udp_destroy(masscan->payloads.udp);
    masscan->payloads.udp = NULL;
  }

  OPENSSL_cleanup();
  return exit_code;
}
