/*
    Read in the configuration for MASSCAN.

    Configuration parameters can be read either from the command-line
    or a configuration file. Long parameters of the --xxxx variety have
    the same name in both.

    Most of the code in this module is for 'nmap' options we don't support.
    That's because we support some 'nmap' options, and I wanted to give
    more feedback for some of them why they don't work as expected, such
    as reminding people that this is an asynchronous scanner.

*/
#include "crypto-base64.h"
#include "logger.h"
#include "masscan-app.h"
#include "masscan-version.h"
#include "masscan.h"
#include "massip-addr.h"
#include "massip-parse.h"
#include "massip-port.h"
#include "massip.h"
#include "proto-banner1.h"
#include "read-service-probes.h"
#include "string_s.h"
#include "templ-payloads.h"
#include "util-cross.h"
#include "util-malloc.h"
#include "vulncheck.h"

#include <ctype.h>
#include <limits.h>

#include <pcre.h>

/***************************************************************************
 ***************************************************************************/
/*static struct Range top_ports_tcp[] = {
    {80, 80},{23, 23}, {443,443},{21,22},{25,25},{3389,3389},{110,110},
    {445,445},
};
static struct Range top_ports_udp[] = {
    {161, 161}, {631, 631}, {137,138},{123,123},{1434},{445,445},{135,135},
    {67,67},
};
static struct Range top_ports_sctp[] = {
    {7, 7},{9, 9},{20,22},{80,80},{179,179},{443,443},{1167,1167},
};*/

/***************************************************************************
 ***************************************************************************/
void masscan_usage() {
  printf("usage:\n");
  printf("masscan -p80,8000-8100 10.0.0.0/8 --rate=10000\n");
  printf(" scan some web ports on 10.x.x.x at 10kpps\n");
  printf("masscan --nmap\n");
  printf(" list those options that are compatible with nmap\n");
  printf("masscan -p80 10.0.0.0/8 --banners -oB <filename>\n");
  printf(" save results of scan in binary format to <filename>\n");
  printf("masscan --open --banners --readscan <filename> -oX <savefile>\n");
  printf(" read binary scan results in <filename> and save them as xml in "
         "<savefile>\n");
  exit(1);
}

/***************************************************************************
 ***************************************************************************/
void print_version() {
  const char *cpu = "unknown";
  const char *compiler = "unknown";
  const char *compiler_version = "unknown";
  const char *os = "unknown";
  printf("\n");
  printf("Masscan version " MASSCAN_VERSION " ( " MASSCAN_REPO_LINK " )\n");
  printf("Compiled on: %s %s\n", __DATE__, __TIME__);

#if defined(_MSC_VER)
#if defined(_M_AMD64) || defined(_M_X64)
  cpu = "x86";
#elif defined(_M_IX86)
  cpu = "x86";
#elif defined(_M_ARM_FP)
  cpu = "arm";
#endif
  compiler = "VisualStudio";
#if _MSC_VER < 1500
  compiler_version = "pre2008";
#elif _MSC_VER == 1500
  compiler_version = "2008";
#elif _MSC_VER == 1600
  compiler_version = "2010";
#elif _MSC_VER == 1700
  compiler_version = "2012";
#elif _MSC_VER == 1800
  compiler_version = "2013";
#else
  compiler_version = "post-2013";
#endif
#elif defined(__GNUC__)
  compiler = "gcc";
  compiler_version = __VERSION__;

#if defined(i386) || defined(__i386) || defined(__i386__)
  cpu = "x86";
#endif

#if defined(__corei7) || defined(__corei7__)
  cpu = "x86-Corei7";
#endif

#endif

#if defined(WIN32)
  os = "Windows";
#elif defined(__linux__)
  os = "Linux";
#elif defined(__APPLE__)
  os = "Apple";
#elif defined(__MACH__)
  os = "MACH";
#elif defined(__FreeBSD__)
  os = "FreeBSD";
#elif defined(__NetBSD__)
  os = "NetBSD";
#elif defined(unix) || defined(__unix) || defined(__unix__)
  os = "Unix";
#endif

  printf("Compiler: %s %s\n", compiler, compiler_version);
  printf("OS: %s\n", os);
  printf("CPU: %s (%u bits)\n", cpu, (unsigned)(sizeof(void *)) * 8);

#if defined(GIT)
  printf("GIT version: %s\n", GIT);
#endif
}

/***************************************************************************
 ***************************************************************************/
void print_nmap_help(void) {
  printf(
      "" MASSCAN_NAME " (" MASSCAN_REPO_LINK ")\n"
      "Usage: " MASSCAN_NAME " [Options] -p{Target-Ports} {Target-IP-Ranges}\n"
      "TARGET SPECIFICATION:\n"
      "  Can pass only IPv4/IPv6 address, CIDR networks, or ranges (non-nmap "
      "style)\n"
      "  Ex: 10.0.0.0/8, 192.168.0.1, 10.0.0.1-10.0.0.254\n"
      "  -iL <inputfilename>: Input from list of hosts/networks\n"
      "  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks\n"
      "  --excludefile <exclude_file>: Exclude list from file\n"
      "  --randomize-hosts: Randomize order of hosts (default)\n"
      "HOST DISCOVERY:\n"
      "  -Pn: Treat all hosts as online (default)\n"
      "  -n: Never do DNS resolution (default)\n"
      "SCAN TECHNIQUES:\n"
      "  -sS: TCP SYN (always on, default)\n"
      "SERVICE/VERSION DETECTION:\n"
      "  --banners: get the banners of the listening service if available. "
      "The\n"
      "    default timeout for waiting to receive data is 30 seconds.\n"
      "PORT SPECIFICATION AND SCAN ORDER:\n"
      "  -p <port ranges>: Only scan specified ports\n"
      "    Ex: -p22; -p1-65535; -p 111,137,80,139,8080\n"
      "TIMING AND PERFORMANCE:\n"
      "  --max-rate <number>: Send packets no faster than <number> per second\n"
      "  --connection-timeout <number>: time in seconds a TCP connection will\n"
      "    timeout while waiting for banner data from a port.\n"
      "FIREWALL/IDS EVASION AND SPOOFING:\n"
      "  -S/--source-ip <IP_Address>: Spoof source address\n"
      "  -e <iface>: Use specified interface\n"
      "  -g/--source-port <portnum>: Use given port number\n"
      "  --ttl <val>: Set IP time-to-live field\n"
      "  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address\n"
      "OUTPUT:\n"
      "  --output-format <format>: Sets output to "
      "binary/list/unicornscan/json/ndjson/grepable/xml\n"
      "  --output-file <file>: Write scan results to file. If --output-format "
      "is\n"
      "     not given default is xml\n"
      "  -oL/-oJ/-oD/-oG/-oB/-oX/-oU <file>: Output scan in "
      "List/JSON/nDjson/Grepable/Binary/XML/Unicornscan format,\n"
      "     respectively, to the given filename. Shortcut for\n"
      "     --output-format <format> --output-file <file>\n"
      "  -v: Increase verbosity level (use -vv or more for greater effect)\n"
      "  -d: Increase debugging level (use -dd or more for greater effect)\n"
      "  --open: Only show open (or possibly open) ports\n"
      "  --packet-trace: Show all packets sent and received\n"
      "  --iflist: Print host interfaces and routes (for debugging)\n"
      "  --append-output: Append to rather than clobber specified output "
      "files\n"
      "  --resume <filename>: Resume an aborted scan\n"
      "MISC:\n"
      "  --send-eth: Send using raw ethernet frames (default)\n"
      "  -V: Print version number\n"
      "  -h: Print this help summary page.\n"
      "EXAMPLES:\n"
      "  masscan -v -sS 192.168.0.0/16 10.0.0.0/8 -p 80\n"
      "  masscan 23.0.0.0/0 -p80 --banners -output-format binary "
      "--output-filename internet.scan\n"
      "  masscan --open --banners --readscan internet.scan -oG "
      "internet_scan.grepable\n"
      "SEE (" MASSCAN_REPO_LINK ") FOR MORE HELP\n"
      "\n");
}

/***************************************************************************
 ***************************************************************************/
static unsigned count_cidr_bits(struct Range range) {
  unsigned i;

  for (i = 0; i < 32; i++) {
    unsigned mask = 0xFFFFFFFF >> i;

    if ((range.begin & ~mask) == (range.end & ~mask)) {
      if ((range.begin & mask) == 0 && (range.end & mask) == mask) {
        return i;
      }
    }
  }

  return 0;
}

/***************************************************************************
 ***************************************************************************/
static unsigned count_cidr6_bits(const struct Range6 *range) {
  unsigned i;

  // https://github.com/robertdavidgraham/masscan/pull/691
  /* the easy case: hi part of addresses are the same */
  if (range->begin.hi == range->end.hi) {
    for (i = 0; i < 64; i++) {
      uint64_t mask = 0xFFFFFFFFffffffffull >> (uint64_t)i;

      if ((range->begin.lo & ~mask) == (range->end.lo & ~mask)) {
        if ((range->begin.lo & mask) == 0 && (range->end.lo & mask) == mask)
          return 64 + i;
      }
    }
    return 0;
  }

  /* the tricky case: hi parts differ */
  for (i = 0; i < 64; i++) {
    uint64_t mask = 0xFFFFFFFFffffffffull >> (uint64_t)i;

    if ((range->begin.hi & ~mask) == (range->end.hi & ~mask)) {
      if ((range->begin.hi & mask) == 0 && range->begin.lo == 0 &&
          (range->end.hi & mask) == mask &&
          range->end.lo == 0xFFFFFFFFffffffffull)
        return i;
    }
  }

  return 0;
}

/***************************************************************************
 ***************************************************************************/
void masscan_save_state(struct Masscan *masscan) {
  char filename[512];
  FILE *fp = NULL;
  int err;

  strcpy_s(filename, sizeof(filename), "paused.conf");
  LOG(LEVEL_ERROR, "                                   "
                   "                                   \r");
  LOG(LEVEL_ERROR, "saving resume file to: %s\n", filename);

  err = fopen_s(&fp, filename, "wt");
  if (err || fp == NULL) {
    LOG(LEVEL_ERROR, "%s: %s\n", filename, strerror(errno));
    exit(1);
  }

  masscan_echo(masscan, fp, 0);
  fclose(fp);
}

#if 0
/*****************************************************************************
 * Read in ranges from a file
 *
 * There can be multiple ranges on a line, delimited by spaces. In fact,
 * millions of ranges can be on a line: there is limit to the line length.
 * That makes reading the file a little bit squirrelly. From one perspective
 * this parser doesn't treat the new-line '\n' any different than other
 * space. But, from another perspective, it has to, because things like
 * comments are terminated by a newline. Also, it has to count the number
 * of lines correctly to print error messages.
 *****************************************************************************/
static void
ranges_from_file(struct RangeList *ranges, const char *filename)
{
    FILE *fp;
    errno_t err;
    unsigned line_number = 0;

    err = fopen_s(&fp, filename, "rt");
    if (err) {
		LOG(LEVEL_ERROR, "%s: %s\n", filename, strerror(errno));
        exit(1); /* HARD EXIT: because if it's an exclusion file, we don't
                  * want to continue. We don't want ANY chance of
                  * accidentally scanning somebody */
    }

    while (!feof(fp)) {
        int c = '\n';

        /* remove leading whitespace */
        while (!feof(fp)) {
            c = getc(fp);
            line_number += (c == '\n');
            if (!isspace(c&0xFF))
                break;
        }

        /* If this is a punctuation, like '#', then it's a comment */
        if (ispunct(c&0xFF)) {
            while (!feof(fp)) {
                c = getc(fp);
                line_number += (c == '\n');
                if (c == '\n') {
                    break;
                }
            }
            /* Loop back to the begining state at the start of a line */
            continue;
        }

        if (c == '\n') {
            continue;
        }

        /*
         * Read in a single entry
         */
        if (!feof(fp)) {
            char address[64];
            size_t i;
            struct Range range;
            unsigned offset = 0;


            /* Grab all bytes until the next space or comma */
            address[0] = (char)c;
            i = 1;
            while (!feof(fp)) {
                c = getc(fp);
                if (c == EOF)
                    break;
                line_number += (c == '\n');
                if (isspace(c&0xFF) || c == ',') {
                    break;
                }
                if (i+1 >= sizeof(address)) {
                    LOG(LEVEL_ERROR, "%s:%u:%u: bad address spec: \"%.*s\"\n",
                            filename, line_number, offset, (int)i, address);
                    exit(1);
                } else
                    address[i] = (char)c;
                i++;
            }
            address[i] = '\0';

            /* parse the address range */
            range = range_parse_ipv4(address, &offset, (unsigned)i);
            if (range.begin == 0xFFFFFFFF && range.end == 0) {
                LOG(LEVEL_ERROR, "%s:%u:%u: bad range spec: \"%.*s\"\n",
                        filename, line_number, offset, (int)i, address);
                exit(1);
            } else {
                rangelist_add_range(ranges, range.begin, range.end);
            }
        }
    }

    fclose(fp);

    /* Target list must be sorted every time it's been changed, 
     * before it can be used */
    rangelist_sort(ranges);
}
#endif

/***************************************************************************
 ***************************************************************************/
static unsigned hexval(char c) {
  if ('0' <= c && c <= '9')
    return (unsigned)(c - '0');
  if ('a' <= c && c <= 'f')
    return (unsigned)(c - 'a' + 10);
  if ('A' <= c && c <= 'F')
    return (unsigned)(c - 'A' + 10);
  return 0xFF;
}

/***************************************************************************
 ***************************************************************************/
static int parse_mac_address(const char *text, macaddress_t *mac) {
  unsigned i;

  for (i = 0; i < 6; i++) {
    unsigned x;
    char c;

    while (isspace(*text & 0xFF) && ispunct(*text & 0xFF))
      text++;

    c = *text;
    if (!isxdigit(c & 0xFF))
      return -1;
    x = hexval(c) << 4;
    text++;

    c = *text;
    if (!isxdigit(c & 0xFF))
      return -1;
    x |= hexval(c);
    text++;

    mac->addr[i] = (unsigned char)x;

    if (ispunct(*text & 0xFF))
      text++;
  }

  return 0;
}

/***************************************************************************
 ***************************************************************************/
static uint64_t parseInt(const char *str) {
  uint64_t result = 0;

  while (*str && isdigit(*str & 0xFF)) {
    result = result * 10 + (*str - '0');
    str++;
  }
  return result;
}

static unsigned parseBoolean(const char *str) {
  if (str == NULL || str[0] == 0)
    return 1;
  if (isdigit((int)str[0])) {
    if (strtoul(str, 0, 0) == 0)
      return 0;
    else
      return 1;
  }
  switch (str[0]) {
  case 't':
  case 'T':
  case 'Y':
  case 'y':
    return 1;
  case 'o':
  case 'O':
    if (str[1] == 'f' || str[1] == 'F')
      return 0;
    else
      return 1;
  case 'n':
  case 'N':
  case 'f':
  case 'F':
    return 0;
  }
  return 1;
}

/***************************************************************************
 * Parses the number of seconds (for rotating files mostly). We do a little
 * more than just parse an integer. We support strings like:
 *
 * hourly
 * daily
 * Week
 * 5days
 * 10-months
 * 3600
 ***************************************************************************/
static time_t parse_time(const char *value) {

  time_t num = 0;
  unsigned is_negative = 0;

  while (*value == '-') {
    is_negative = 1;
    value++;
  }

  while (isdigit(value[0] & 0xFF)) {
    num = num * 10 + (value[0] - '0');
    value++;
  }
  while (ispunct((int)value[0]) || isspace((int)value[0]))
    value++;

  if (isalpha((int)value[0]) && num == 0)
    num = 1;

  if (value[0] == '\0')
    return num;

  switch (tolower(value[0])) {
  case 's':
    num *= 1;
    break;
  case 'm':
    num *= 60;
    break;
  case 'h':
    num *= 60 * 60;
    break;
  case 'd':
    num *= 24 * 60 * 60;
    break;
  case 'w':
    num *= 24 * 60 * 60 * 7;
    break;
  default:
    LOG(LEVEL_ERROR, "--rotate-offset: unknown character\n");
    exit(1);
  }
  if (num >= 24 * 60 * 60) {
    LOG(LEVEL_ERROR, "--rotate-offset: value is greater than 1 day\n");
    exit(1);
  }
  if (is_negative)
    num = 24 * 60 * 60 - num;

  return num;
}

/***************************************************************************
 * Parses a size integer, which can be suffixed with "tera", "giga",
 * "mega", and "kilo". These numbers are in units of 1024 so suck it.
 ***************************************************************************/
static uint64_t parseSize(const char *value) {
  uint64_t num = 0;

  while (isdigit(value[0] & 0xFF)) {
    num = num * 10 + (value[0] - '0');
    value++;
  }
  while (ispunct((int)value[0]) || isspace((int)value[0]))
    value++;

  if (isalpha((int)value[0]) && num == 0)
    num = 1;

  if (value[0] == '\0')
    return num;

  switch (tolower(value[0])) {
  case 'k': /* kilobyte */
    num *= 1024ULL;
    break;
  case 'm': /* megabyte */
    num *= 1024ULL * 1024ULL;
    break;
  case 'g': /* gigabyte */
    num *= 1024ULL * 1024ULL * 1024ULL;
    break;
  case 't': /* terabyte, 'cause we roll that way */
    num *= 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    break;
  case 'p': /* petabyte, 'cause we are awesome */
    num *= 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    break;
  case 'e': /* exabyte, now that's just silly */
    num *= 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    break;
  default:
    LOG(LEVEL_ERROR, "--rotate-size: unknown character\n");
    exit(1);
  }
  return num;
}

/***************************************************************************
 ***************************************************************************/
static int is_power_of_two(uint64_t x) {
  while ((x & 1) == 0)
    x >>= 1;
  return x == 1;
}

/***************************************************************************
 * Tests if the named parameter on the command-line. We do a little
 * more than a straight string compare, because I get confused
 * whether parameter have punctuation. Is it "--excludefile" or
 * "--exclude-file"? I don't know if it's got that dash. Screw it,
 * I'll just make the code so it don't care.
 ***************************************************************************/
static int EQUALS(const char *lhs, const char *rhs) {
  for (;;) {
    while (*lhs == '-' || *lhs == '.' || *lhs == '_')
      lhs++;
    while (*rhs == '-' || *rhs == '.' || *rhs == '_')
      rhs++;
    if (*lhs == '\0' && *rhs == '[')
      return 1; /*arrays*/
    if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
      return 0;
    if (*lhs == '\0')
      return 1;
    lhs++;
    rhs++;
  }
}

static int EQUALSx(const char *lhs, const char *rhs, size_t rhs_length) {
  for (;;) {
    while (*lhs == '-' || *lhs == '.' || *lhs == '_')
      lhs++;
    while (*rhs == '-' || *rhs == '.' || *rhs == '_')
      rhs++;
    if (*lhs == '\0' && *rhs == '[')
      return 1; /*arrays*/
    if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
      return 0;
    if (*lhs == '\0')
      return 1;
    lhs++;
    rhs++;
    if (--rhs_length == 0)
      return 1;
  }
}

static size_t INDEX_OF(const char *str, char c) {
  size_t i;
  for (i = 0; str[i] && str[i] != c; i++)
    ;
  return i;
}

static size_t ARRAY(const char *rhs) {
  const char *p = strchr(rhs, '[');
  if (p == NULL) {
    return 0;
  } else {
    p++;
  }
  return (size_t)parseInt(p);
}

static void config_top_ports(struct Masscan *masscan, unsigned n) {
  unsigned i;
  static const unsigned short top_tcp_ports[] = {
      1,     3,     4,     6,     7,     9,     13,    17,    19,    20,
      21,    22,    23,    24,    25,    26,    30,    32,    33,    37,
      42,    43,    49,    53,    70,    79,    80,    81,    82,    83,
      84,    85,    88,    89,    90,    99,    100,   106,   109,   110,
      111,   113,   119,   125,   135,   139,   143,   144,   146,   161,
      163,   179,   199,   211,   212,   222,   254,   255,   256,   259,
      264,   280,   301,   306,   311,   340,   366,   389,   406,   407,
      416,   417,   425,   427,   443,   444,   445,   458,   464,   465,
      481,   497,   500,   512,   513,   514,   515,   524,   541,   543,
      544,   545,   548,   554,   555,   563,   587,   593,   616,   617,
      625,   631,   636,   646,   648,   666,   667,   668,   683,   687,
      691,   700,   705,   711,   714,   720,   722,   726,   749,   765,
      777,   783,   787,   800,   801,   808,   843,   873,   880,   888,
      898,   900,   901,   902,   903,   911,   912,   981,   987,   990,
      992,   993,   995,   999,   1000,  1001,  1002,  1007,  1009,  1010,
      1011,  1021,  1022,  1023,  1024,  1025,  1026,  1027,  1028,  1029,
      1030,  1031,  1032,  1033,  1034,  1035,  1036,  1037,  1038,  1039,
      1040,  1041,  1042,  1043,  1044,  1045,  1046,  1047,  1048,  1049,
      1050,  1051,  1052,  1053,  1054,  1055,  1056,  1057,  1058,  1059,
      1060,  1061,  1062,  1063,  1064,  1065,  1066,  1067,  1068,  1069,
      1070,  1071,  1072,  1073,  1074,  1075,  1076,  1077,  1078,  1079,
      1080,  1081,  1082,  1083,  1084,  1085,  1086,  1087,  1088,  1089,
      1090,  1091,  1092,  1093,  1094,  1095,  1096,  1097,  1098,  1099,
      1100,  1102,  1104,  1105,  1106,  1107,  1108,  1110,  1111,  1112,
      1113,  1114,  1117,  1119,  1121,  1122,  1123,  1124,  1126,  1130,
      1131,  1132,  1137,  1138,  1141,  1145,  1147,  1148,  1149,  1151,
      1152,  1154,  1163,  1164,  1165,  1166,  1169,  1174,  1175,  1183,
      1185,  1186,  1187,  1192,  1198,  1199,  1201,  1213,  1216,  1217,
      1218,  1233,  1234,  1236,  1244,  1247,  1248,  1259,  1271,  1272,
      1277,  1287,  1296,  1300,  1301,  1309,  1310,  1311,  1322,  1328,
      1334,  1352,  1417,  1433,  1434,  1443,  1455,  1461,  1494,  1500,
      1501,  1503,  1521,  1524,  1533,  1556,  1580,  1583,  1594,  1600,
      1641,  1658,  1666,  1687,  1688,  1700,  1717,  1718,  1719,  1720,
      1721,  1723,  1755,  1761,  1782,  1783,  1801,  1805,  1812,  1839,
      1840,  1862,  1863,  1864,  1875,  1900,  1914,  1935,  1947,  1971,
      1972,  1974,  1984,  1998,  1999,  2000,  2001,  2002,  2003,  2004,
      2005,  2006,  2007,  2008,  2009,  2010,  2013,  2020,  2021,  2022,
      2030,  2033,  2034,  2035,  2038,  2040,  2041,  2042,  2043,  2045,
      2046,  2047,  2048,  2049,  2065,  2068,  2099,  2100,  2103,  2105,
      2106,  2107,  2111,  2119,  2121,  2126,  2135,  2144,  2160,  2161,
      2170,  2179,  2190,  2191,  2196,  2200,  2222,  2251,  2260,  2288,
      2301,  2323,  2366,  2381,  2382,  2383,  2393,  2394,  2399,  2401,
      2492,  2500,  2522,  2525,  2557,  2601,  2602,  2604,  2605,  2607,
      2608,  2638,  2701,  2702,  2710,  2717,  2718,  2725,  2800,  2809,
      2811,  2869,  2875,  2909,  2910,  2920,  2967,  2968,  2998,  3000,
      3001,  3003,  3005,  3006,  3007,  3011,  3013,  3017,  3030,  3031,
      3052,  3071,  3077,  3128,  3168,  3211,  3221,  3260,  3261,  3268,
      3269,  3283,  3300,  3301,  3306,  3322,  3323,  3324,  3325,  3333,
      3351,  3367,  3369,  3370,  3371,  3372,  3389,  3390,  3404,  3476,
      3493,  3517,  3527,  3546,  3551,  3580,  3659,  3689,  3690,  3703,
      3737,  3766,  3784,  3800,  3801,  3809,  3814,  3826,  3827,  3828,
      3851,  3869,  3871,  3878,  3880,  3889,  3905,  3914,  3918,  3920,
      3945,  3971,  3986,  3995,  3998,  4000,  4001,  4002,  4003,  4004,
      4005,  4006,  4045,  4111,  4125,  4126,  4129,  4224,  4242,  4279,
      4321,  4343,  4443,  4444,  4445,  4446,  4449,  4550,  4567,  4662,
      4848,  4899,  4900,  4998,  5000,  5001,  5002,  5003,  5004,  5009,
      5030,  5033,  5050,  5051,  5054,  5060,  5061,  5080,  5087,  5100,
      5101,  5102,  5120,  5190,  5200,  5214,  5221,  5222,  5225,  5226,
      5269,  5280,  5298,  5357,  5405,  5414,  5431,  5432,  5440,  5500,
      5510,  5544,  5550,  5555,  5560,  5566,  5631,  5633,  5666,  5678,
      5679,  5718,  5730,  5800,  5801,  5802,  5810,  5811,  5815,  5822,
      5825,  5850,  5859,  5862,  5877,  5900,  5901,  5902,  5903,  5904,
      5906,  5907,  5910,  5911,  5915,  5922,  5925,  5950,  5952,  5959,
      5960,  5961,  5962,  5963,  5987,  5988,  5989,  5998,  5999,  6000,
      6001,  6002,  6003,  6004,  6005,  6006,  6007,  6009,  6025,  6059,
      6100,  6101,  6106,  6112,  6123,  6129,  6156,  6346,  6389,  6502,
      6510,  6543,  6547,  6565,  6566,  6567,  6580,  6646,  6666,  6667,
      6668,  6669,  6689,  6692,  6699,  6779,  6788,  6789,  6792,  6839,
      6881,  6901,  6969,  7000,  7001,  7002,  7004,  7007,  7019,  7025,
      7070,  7100,  7103,  7106,  7200,  7201,  7402,  7435,  7443,  7496,
      7512,  7625,  7627,  7676,  7741,  7777,  7778,  7800,  7911,  7920,
      7921,  7937,  7938,  7999,  8000,  8001,  8002,  8007,  8008,  8009,
      8010,  8011,  8021,  8022,  8031,  8042,  8045,  8080,  8081,  8082,
      8083,  8084,  8085,  8086,  8087,  8088,  8089,  8090,  8093,  8099,
      8100,  8180,  8181,  8192,  8193,  8194,  8200,  8222,  8254,  8290,
      8291,  8292,  8300,  8333,  8383,  8400,  8402,  8443,  8500,  8600,
      8649,  8651,  8652,  8654,  8701,  8800,  8873,  8888,  8899,  8994,
      9000,  9001,  9002,  9003,  9009,  9010,  9011,  9040,  9050,  9071,
      9080,  9081,  9090,  9091,  9099,  9100,  9101,  9102,  9103,  9110,
      9111,  9200,  9207,  9220,  9290,  9415,  9418,  9485,  9500,  9502,
      9503,  9535,  9575,  9593,  9594,  9595,  9618,  9666,  9876,  9877,
      9878,  9898,  9900,  9917,  9929,  9943,  9944,  9968,  9998,  9999,
      10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025,
      10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628,
      10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456,
      13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003,
      15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113,
      16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315,
      19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828,
      21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352,
      27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337,
      32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777,
      32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899,
      34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176,
      44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156,
      49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176,
      49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500,
      50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328,
      55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020,
      60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389};
  struct RangeList *ports = &masscan->targets.ports;

  if (masscan->scan_type.tcp) {
    for (i = 0; i < n && i < ARRAY_SIZE(top_tcp_ports); i++)
      rangelist_add_range(ports, top_tcp_ports[i], top_tcp_ports[i]);
  }
  if (masscan->scan_type.udp) {
    for (i = 0; i < n && i < ARRAY_SIZE(top_tcp_ports); i++)
      rangelist_add_range(ports, top_tcp_ports[i], top_tcp_ports[i]);
  }

  /* Targets must be sorted after every change, before being used */
  rangelist_sort(ports);
}

/***************************************************************************
 ***************************************************************************/
static int isInteger(const char *value) {
  size_t i;

  if (value == NULL) {
    return false;
  }

  for (i = 0; value[i]; i++) {
    if (!isdigit(value[i] & 0xFF)) {
      return false;
    }
  }
  return true;
}

/***************************************************************************
 ***************************************************************************/
typedef int (*SET_PARAMETER)(struct Masscan *masscan, const char *name,
                             const char *value);
typedef void (*CLENUP_PARAMETER)(struct Masscan *masscan, const char *name);
enum { CONF_OK, CONF_WARN, CONF_ERR };

static int SET_arpscan(struct Masscan *masscan, const char *name,
                       const char *value) {
  struct Range range;
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    if (masscan->scan_type.arp || masscan->echo_all)
      fprintf(masscan->echo, "arpscan = %s\n",
              masscan->scan_type.arp ? "true" : "false");
    return CONF_OK;
  }

  range.begin = Templ_ARP;
  range.end = Templ_ARP_last;
  rangelist_add_range2(&masscan->targets.ports, &range);
  rangelist_sort(&masscan->targets.ports);
  masscan_set_parameter(masscan, "router-mac", "ff-ff-ff-ff-ff-ff");
  masscan->scan_type.arp = true;
  LOG(LEVEL_DEBUG_3, "--arpscan\n");
  return CONF_OK;
}

static void CLEANUP_arpscan(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_banners(struct Masscan *masscan, const char *name,
                       const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->is_banners || masscan->echo_all)
      fprintf(masscan->echo, "banners = %s\n",
              masscan->is_banners ? "true" : "false");
    return CONF_OK;
  }

  if (EQUALS("banners", name) || EQUALS("banner", name)) {
    masscan->is_banners = parseBoolean(value);
  } else if (EQUALS("nobanners", name) || EQUALS("nobanner", name)) {
    masscan->is_banners = !parseBoolean(value);
  } else {
    LOG(LEVEL_ERROR, "Not implement banners alias %s\n", name);
    return CONF_ERR;
  }
  return CONF_OK;
}

static void CLEANUP_banners(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(masscan);
  UNUSEDPARM(name);
  return;
}

static int SET_dynamic_ssl(struct Masscan *masscan, const char *name,
                           const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->is_ssl_dynamic || masscan->echo_all)
      fprintf(masscan->echo, "dynamic-ssl = %s\n",
              masscan->is_ssl_dynamic ? "true" : "false");
    return CONF_OK;
  }

  masscan->is_ssl_dynamic = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_dynamic_ssl(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_regex(struct Masscan *masscan, const char *name,
                     const char *value) {
  const char *error;
  int erroffset;
  pcre *re;
  pcre_extra *re_extra;
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->regex || masscan->echo_all)
      fprintf(masscan->echo, "regex = %s\n", masscan->regex_src);
    return CONF_OK;
  }

  if (masscan->regex_src) {
    free(masscan->regex_src);
    masscan->regex_src = NULL;
  }
  if (masscan->regex) {
    pcre_free(masscan->regex);
    masscan->regex = NULL;
  }
  if (masscan->regex_extra) {
    pcre_free_study(masscan->regex_extra);
    masscan->regex_extra = NULL;
  }

  re = pcre_compile(value, PCRE_CASELESS, &error, &erroffset, NULL);
  if (!re) {
    LOG(LEVEL_ERROR, "Failed regex compile %s at offset %d: %s\n", value,
        erroffset, error);
    return CONF_ERR;
  }
  re_extra = pcre_study(re, 0, &error);
  if (!re_extra) {
    LOG(LEVEL_ERROR, "Failed regex study %s: %s\n", value, error);
    pcre_free(re);
    return CONF_ERR;
  }

  masscan->regex = re;
  masscan->regex_extra = re_extra;
  masscan->regex_src = STRDUP(value);

  return CONF_OK;
}

static void CLEANUP_regex(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  if (masscan->regex_src != NULL) {
    free(masscan->regex_src);
    masscan->regex_src = NULL;
  }

  if (masscan->regex_extra != NULL) {
    pcre_free_study(masscan->regex_extra);
    masscan->regex_extra = NULL;
  }

  if (masscan->regex != NULL) {
    pcre_free(masscan->regex);
    masscan->regex = NULL;
  }

  return;
}

static int SET_dynamic_set_host(struct Masscan *masscan, const char *name,
                                const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->is_dynamic_set_host || masscan->echo_all)
      fprintf(masscan->echo, "dynamic_set_host = %s\n",
              masscan->is_dynamic_set_host ? "true" : "false");
    return CONF_OK;
  }

  masscan->is_dynamic_set_host = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_dynamic_set_host(struct Masscan *masscan,
                                     const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_regex_only_banners(struct Masscan *masscan, const char *name,
                                  const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->is_regex_only_banners || masscan->echo_all)
      fprintf(masscan->echo, "regex-only-banners = %s\n",
              masscan->is_regex_only_banners ? "true" : "false");
    return CONF_OK;
  }

  masscan->is_regex_only_banners = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_regex_only_banners(struct Masscan *masscan,
                                       const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_capture(struct Masscan *masscan, const char *name,
                       const char *value) {
  if (masscan->echo) {
    if (!masscan->is_capture_cert || masscan->echo_all)
      fprintf(masscan->echo, "%scapture = cert\n",
              masscan->is_capture_cert ? "" : "no");
    if (masscan->is_capture_servername || masscan->echo_all)
      fprintf(masscan->echo, "%scapture = servername\n",
              masscan->is_capture_servername ? "" : "no");
    if (masscan->is_capture_html || masscan->echo_all)
      fprintf(masscan->echo, "%scapture = html\n",
              masscan->is_capture_html ? "" : "no");
    if (masscan->is_capture_heartbleed || masscan->echo_all)
      fprintf(masscan->echo, "%scapture = heartbleed\n",
              masscan->is_capture_heartbleed ? "" : "no");
    if (masscan->is_capture_ticketbleed || masscan->echo_all)
      fprintf(masscan->echo, "%scapture = ticketbleed\n",
              masscan->is_capture_ticketbleed ? "" : "no");
    return CONF_OK;
  }

  if (EQUALS("capture", name)) {
    if (EQUALS("cert", value))
      masscan->is_capture_cert = true;
    else if (EQUALS("servername", value))
      masscan->is_capture_servername = true;
    else if (EQUALS("html", value))
      masscan->is_capture_html = true;
    else if (EQUALS("heartbleed", value))
      masscan->is_capture_heartbleed = true;
    else if (EQUALS("ticketbleed", value))
      masscan->is_capture_ticketbleed = true;
    else {
      LOG(LEVEL_ERROR, "FAIL: %s: unknown capture type\n", value);
      return CONF_ERR;
    }
  } else if (EQUALS("nocapture", name)) {
    if (EQUALS("cert", value))
      masscan->is_capture_cert = false;
    else if (EQUALS("servername", value))
      masscan->is_capture_servername = false;
    else if (EQUALS("html", value))
      masscan->is_capture_html = false;
    else if (EQUALS("heartbleed", value))
      masscan->is_capture_heartbleed = false;
    else if (EQUALS("ticketbleed", value))
      masscan->is_capture_ticketbleed = false;
    else {
      LOG(LEVEL_ERROR, "FAIL: %s: unknown nocapture type\n", value);
      return CONF_ERR;
    }
  }
  return CONF_OK;
}

static void CLEANUP_capture(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_hello(struct Masscan *masscan, const char *name,
                     const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->is_hello_ssl) {
      fprintf(masscan->echo, "hello = ssl\n");
    } else if (masscan->is_hello_smbv1) {
      fprintf(masscan->echo, "hello = smbv1\n");
    } else if (masscan->is_hello_http) {
      fprintf(masscan->echo, "hello = http\n");
    }
    return CONF_OK;
  }

  if (EQUALS("ssl", value))
    masscan->is_hello_ssl = true;
  else if (EQUALS("smbv1", value))
    masscan->is_hello_smbv1 = true;
  else if (EQUALS("http", value))
    masscan->is_hello_http = true;
  else {
    LOG(LEVEL_ERROR, "FAIL: %s: unknown hello type\n", value);
    return CONF_ERR;
  }
  return CONF_OK;
}

static void CLEANUP_hello(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_hello_file(struct Masscan *masscan, const char *name,
                          const char *value) {
  size_t index;
  FILE *fp = NULL;
  int x;
  char buf[16384];
  char buf2[16384];
  size_t bytes_read;
  size_t bytes_encoded;
  char foo[64];

  if (masscan->echo) {
    // Echoed as a string "hello-string" that was originally read
    // from a file, not the "hello-filename"
    return CONF_OK;
  }

  index = ARRAY(name);
  if (index >= 65536) {
    LOG(LEVEL_ERROR, "%s: bad index\n", name);
    return CONF_ERR;
  }

  /* When connecting via TCP, send this file */
  x = fopen_s(&fp, value, "rb");
  if (x || fp == NULL) {
    LOG(LEVEL_ERROR, "[FAILED] could not read hello file\n");
    LOG(LEVEL_ERROR, "%s: %s\n", value, strerror(errno));
    return CONF_ERR;
  }

  bytes_read = fread(buf, 1, sizeof(buf), fp);
  if (bytes_read == 0) {
    LOG(LEVEL_ERROR, "[FAILED] could not read hello file\n");
    LOG(LEVEL_ERROR, "%s: %s\n", value, strerror(errno));
    fclose(fp);
    return CONF_ERR;
  }
  fclose(fp);

  bytes_encoded = base64_encode(buf2, sizeof(buf2) - 1, buf, bytes_read);
  buf2[bytes_encoded] = '\0';
  sprintf_s(foo, sizeof(foo), "hello-string[%" PRIuPTR "]", index);
  masscan_set_parameter(masscan, foo, buf2);
  return CONF_OK;
}

static void CLEANUP_hello_file(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_hello_string(struct Masscan *masscan, const char *name,
                            const char *value) {
  size_t index;
  struct TcpCfgPayloads *pay;

  if (masscan->echo) {
    for (pay = masscan->payloads.tcp; pay; pay = pay->next) {
      fprintf(masscan->echo, "hello-string[%u] = %s\n", pay->port,
              pay->payload_base64);
    }
    return CONF_OK;
  }

  index = ARRAY(name);
  if (index >= 65536) {
    LOG(LEVEL_ERROR, "%s: bad index\n", name);
    return CONF_ERR;
  }
  pay = MALLOC(sizeof(*pay));
  pay->payload_base64 = STRDUP(value);
  pay->port = (unsigned)index;
  pay->next = masscan->payloads.tcp;
  masscan->payloads.tcp = pay;
  return CONF_OK;
}

static void CLEANUP_hello_string(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  struct TcpCfgPayloads *pay;

  pay = masscan->payloads.tcp;
  while (pay) {
    struct TcpCfgPayloads *pay_free;
    pay_free = pay;
    pay = pay->next;
    free(pay_free->payload_base64);
    free(pay_free);
  }
  return;
}

static int SET_hello_timeout(struct Masscan *masscan, const char *name,
                             const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->tcp_hello_timeout || masscan->echo_all)
      fprintf(masscan->echo, "hello-timeout = %u\n",
              masscan->tcp_hello_timeout);
    return CONF_OK;
  }

  masscan->tcp_hello_timeout = (unsigned)parseInt(value);
  return CONF_OK;
}

static void CLEANUP_hello_timeout(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_status_ndjson(struct Masscan *masscan, const char *name,
                             const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->output.is_status_ndjson || masscan->echo_all)
      fprintf(masscan->echo, "ndjson-status = %s\n",
              masscan->output.is_status_ndjson ? "true" : "false");
    return CONF_OK;
  }
  masscan->output.is_status_ndjson = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_status_ndjson(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_http_cookie(struct Masscan *masscan, const char *name,
                           const char *value) {
  char *newvalue;
  size_t value_length;
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->http.cookies_count || masscan->echo_all) {
      size_t i;
      for (i = 0; i < masscan->http.cookies_count; i++) {
        fprintf(masscan->echo, "http-cookie = %.*s\n",
                (unsigned)masscan->http.cookies[i].value_length,
                masscan->http.cookies[i].value);
      }
    }
    return CONF_OK;
  }

  /* allocate new value */
  value_length = strlen(value);
  newvalue = STRDUP(value);

  /* Add to our list of headers */
  if (masscan->http.cookies_count < ARRAY_SIZE(masscan->http.cookies)) {
    size_t x = masscan->http.cookies_count;
    masscan->http.cookies[x].value = newvalue;
    masscan->http.cookies[x].value_length = value_length;
    masscan->http.cookies_count++;
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "http-cookie overflow: %s\n", newvalue);
  free(newvalue);
  return CONF_ERR;
}

static void CLEANUP_http_cookie(struct Masscan *masscan, const char *name) {
  size_t i;
  UNUSEDPARM(name);

  for (i = 0; i < masscan->http.cookies_count; i++) {
    masscan->http.cookies[i].value_length = 0;
    free(masscan->http.cookies[i].value);
    masscan->http.cookies[i].value = NULL;
  }
  masscan->http.cookies_count = 0;
  return;
}

static int SET_http_header(struct Masscan *masscan, const char *name,
                           const char *value) {
  char *newname = NULL;
  size_t name_length = 0;
  char *newvalue = NULL;
  size_t value_length = 0;

  if (masscan->echo) {
    if (masscan->http.headers_count || masscan->echo_all) {
      size_t i;
      for (i = 0; i < masscan->http.headers_count; i++) {
        if (masscan->http.headers[i].name == NULL) {
          continue;
        }
        fprintf(masscan->echo, "http-header = %s:%.*s\n",
                masscan->http.headers[i].name,
                (unsigned)masscan->http.headers[i].value_length,
                masscan->http.headers[i].value);
      }
    }
    return CONF_OK;
  }

  /* allocate a new name */
  name += 11;
  if (*name == '[') {
    /* Specified as: "--http-header[name] value" */
    while (ispunct(*name)) {
      name++;
    }
    name_length = strlen(name);
    while (name_length && ispunct(name[name_length - 1])) {
      name_length--;
    }
    newname = MALLOC(name_length + 1);
    memcpy(newname, name, name_length + 1);
    newname[name_length] = '\0';
  } else if (strchr(value, ':')) {
    /* Specified as: "--http-header Name:value" */
    name_length = INDEX_OF(value, ':');
    newname = MALLOC(name_length + 1);
    memcpy(newname, value, name_length + 1);

    /* Trim the value */
    value = value + name_length + 1;
    while (*value && isspace(*value & 0xFF)) {
      value++;
    }

    /* Trim the name */
    while (name_length && isspace(newname[name_length - 1] & 0xFF)) {
      name_length--;
    }
    newname[name_length] = '\0';
  } else {
    LOG(LEVEL_ERROR, "[-] --http-header needs both a name and value\n");
    LOG(LEVEL_ERROR, "    hint: \"--http-header Name:value\"\n");
    return CONF_ERR;
  }

  /* allocate new value */
  value_length = strlen(value);
  newvalue = STRDUP(value);

  /* Add to our list of headers */
  if (masscan->http.headers_count < ARRAY_SIZE(masscan->http.headers)) {
    size_t x = masscan->http.headers_count;
    masscan->http.headers[x].name = newname;
    masscan->http.headers[x].value = newvalue;
    masscan->http.headers[x].value_length = value_length;
    masscan->http.headers_count++;
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "http-header overflow: %s %s\n", newname, newvalue);
  free(newname);
  free(newvalue);
  return CONF_ERR;
}

static void CLEANUP_http_header(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  size_t i;

  for (i = 0; i < masscan->http.headers_count; i++) {
    masscan->http.headers[i].value_length = 0;
    free(masscan->http.headers[i].value);
    masscan->http.headers[i].value = NULL;
    free(masscan->http.headers[i].name);
    masscan->http.headers[i].name = NULL;
  }

  masscan->http.headers_count = 0;
  return;
}

static int SET_http_method(struct Masscan *masscan, const char *name,
                           const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->http.method) {
      fprintf(masscan->echo, "http-method = %.*s\n",
              (unsigned)masscan->http.method_length, masscan->http.method);
    }
    return CONF_OK;
  }

  if (masscan->http.method) {
    free(masscan->http.method);
  }
  masscan->http.method_length = strlen(value);
  masscan->http.method = STRDUP(value);
  return CONF_OK;
}

static void CLEANUP_http_method(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);

  free(masscan->http.method);
  masscan->http.method = NULL;
  masscan->http.method_length = 0;
  return;
}

static int SET_http_url(struct Masscan *masscan, const char *name,
                        const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->http.url) {
      fprintf(masscan->echo, "http-url = %.*s\n",
              (unsigned)masscan->http.url_length, masscan->http.url);
    }
    return CONF_OK;
  }

  if (masscan->http.url) {
    free(masscan->http.url);
  }
  masscan->http.url = STRDUP(value);
  masscan->http.url_length = strlen(value);
  return CONF_OK;
}

static void CLEANUP_http_url(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);

  if (masscan->http.url) {
    free(masscan->http.url);
    masscan->http.url = NULL;
    masscan->http.url_length = 0;
  }
  return;
}

static int SET_http_version(struct Masscan *masscan, const char *name,
                            const char *value) {
  UNUSEDPARM(name);
  if (masscan->echo) {
    if (masscan->http.version) {
      fprintf(masscan->echo, "http-version = %.*s\n",
              (unsigned)masscan->http.version_length, masscan->http.version);
    }
    return 0;
  }
  if (masscan->http.version)
    free(masscan->http.version);
  masscan->http.version_length = strlen(value);
  masscan->http.version = MALLOC(masscan->http.version_length + 1);
  memcpy(masscan->http.version, value, masscan->http.version_length + 1);
  return CONF_OK;
}

static void CLEANUP_http_version(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);

  if (masscan->http.version) {
    free(masscan->http.version);
    masscan->http.version = NULL;
    masscan->http.version_length = 0;
  }
  return;
}

static int SET_http_host(struct Masscan *masscan, const char *name,
                         const char *value) {

  UNUSEDPARM(name);
  if (masscan->echo) {
    if (masscan->http.host) {
      fprintf(masscan->echo, "http-host = %.*s\n",
              (unsigned)masscan->http.host_length, masscan->http.host);
    }
    return CONF_OK;
  }
  if (masscan->http.host) {
    free(masscan->http.host);
  }
  masscan->http.host_length = strlen(value);
  masscan->http.host = STRDUP(value);
  return CONF_OK;
}

static void CLEANUP_http_host(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);

  if (masscan->http.host) {
    free(masscan->http.host);
    masscan->http.host = NULL;
    masscan->http.host_length = 0;
  }
  return;
}

static int SET_http_user_agent(struct Masscan *masscan, const char *name,
                               const char *value) {
  UNUSEDPARM(name);
  if (masscan->echo) {
    if (masscan->http.user_agent) {
      fprintf(masscan->echo, "http-user-agent = %.*s\n",
              (unsigned)masscan->http.user_agent_length,
              masscan->http.user_agent);
    }
    return 0;
  }
  if (masscan->http.user_agent) {
    free(masscan->http.user_agent);
  }
  masscan->http.user_agent_length = strlen(value);
  masscan->http.user_agent = STRDUP(value);
  return CONF_OK;
}

static void CLEANUP_http_user_agent(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);

  if (masscan->http.user_agent) {
    free(masscan->http.user_agent);
    masscan->http.user_agent = NULL;
    masscan->http.user_agent_length = 0;
  }
  return;
}

static int SET_http_payload(struct Masscan *masscan, const char *name,
                            const char *value) {
  UNUSEDPARM(name);
  if (masscan->echo) {
    if (masscan->http.payload) {
      fprintf(masscan->echo, "http-payload = %.*s\n",
              (unsigned)masscan->http.payload_length, masscan->http.payload);
    }
    return 0;
  }
  masscan->http.payload_length = strlen(value);
  masscan->http.payload =
      REALLOC(masscan->http.payload, masscan->http.payload_length + 1);
  memcpy(masscan->http.payload, value, masscan->http.payload_length + 1);
  return CONF_OK;
}

static void CLEANUP_http_payload(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);

  if (masscan->http.payload) {
    free(masscan->http.payload);
    masscan->http.payload = NULL;
    masscan->http.payload_length = 0;
  }
  return;
}

static int SET_status_json(struct Masscan *masscan, const char *name,
                           const char *value) {
  /* NOTE: this is here just to warn people they mistyped it */
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "[-] FAIL: %s not supported, use --status-ndjson\n", name);
  LOG(LEVEL_ERROR, "    hint: new-line delimited JSON status is what we use\n");
  return CONF_ERR;
}

static void CLEANUP_status_json(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_min_packet(struct Masscan *masscan, const char *name,
                          const char *value) {

  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->min_packet_size != 60 || masscan->echo_all)
      fprintf(masscan->echo, "min-packet = %u\n", masscan->min_packet_size);
    return CONF_OK;
  }

  masscan->min_packet_size = (unsigned)parseInt(value);
  return CONF_OK;
}

static void CLEANUP_min_packet(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_noreset(struct Masscan *masscan, const char *name,
                       const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->is_noreset || masscan->echo_all)
      fprintf(masscan->echo, "noreset = %s\n",
              masscan->is_noreset ? "true" : "false");
    return CONF_OK;
  }

  masscan->is_noreset = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_noreset(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_nmap_payloads(struct Masscan *masscan, const char *name,
                             const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    char *filename = masscan->payloads.nmap_payloads_filename;
    if ((filename && filename[0]) || masscan->echo_all) {
      if (filename) {
        fprintf(masscan->echo, "nmap-payloads = %s\n", filename);
      } else {
        fprintf(masscan->echo, "nmap-payloads = \n");
      }
    }
    return CONF_OK;
  }

  if (masscan->payloads.nmap_payloads_filename) {
    free(masscan->payloads.nmap_payloads_filename);
  }
  masscan->payloads.nmap_payloads_filename = STRDUP(value);
  return CONF_OK;
}

static void CLEANUP_nmap_payloads(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  if (masscan->payloads.nmap_payloads_filename) {
    free(masscan->payloads.nmap_payloads_filename);
    masscan->payloads.nmap_payloads_filename = NULL;
  }
  return;
}

static int SET_nmap_service_probes(struct Masscan *masscan, const char *name,
                                   const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    char *filename = masscan->payloads.nmap_service_probes_filename;
    if ((filename && filename[0]) || masscan->echo_all) {
      if (filename) {
        fprintf(masscan->echo, "nmap-service-probes = %s\n", filename);
      } else {
        fprintf(masscan->echo, "nmap-service-probes = \n");
      }
    }
    return CONF_OK;
  }

  if (masscan->payloads.nmap_service_probes_filename) {
    free(masscan->payloads.nmap_service_probes_filename);
  }
  masscan->payloads.nmap_service_probes_filename = STRDUP(value);
  return CONF_OK;
}

static void CLEANUP_nmap_service_probes(struct Masscan *masscan,
                                        const char *name) {
  UNUSEDPARM(name);

  if (masscan->payloads.nmap_service_probes_filename) {
    free(masscan->payloads.nmap_service_probes_filename);
    masscan->payloads.nmap_service_probes_filename = NULL;
  }
  return;
}

static int SET_output_append(struct Masscan *masscan, const char *name,
                             const char *value) {

  if (masscan->echo) {
    if (masscan->output.is_append || masscan->echo_all) {
      fprintf(masscan->echo, "output-append = %s\n",
              masscan->output.is_append ? "true" : "false");
    }
    return CONF_OK;
  }

  if (EQUALS("overwrite", name) || !parseBoolean(value)) {
    masscan->output.is_append = false;
  } else {
    masscan->output.is_append = true;
  }
  return CONF_OK;
}

static void CLEANUP_output_append(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_output_filename(struct Masscan *masscan, const char *name,
                               const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->output.filename[0] || masscan->echo_all) {
      fprintf(masscan->echo, "output-filename = %s\n",
              masscan->output.filename);
    }
    return CONF_OK;
  }

  if (masscan->output.format == Output_Default) {
    masscan->output.format = Output_XML; /*TODO: Why is the default XML?*/
  }
  strcpy_s(masscan->output.filename, sizeof(masscan->output.filename), value);
  return CONF_OK;
}

static void CLEANUP_output_filename(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_output_filename_ssl_keys(struct Masscan *masscan,
                                        const char *name, const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->output.filename_ssl_keys[0] || masscan->echo_all) {
      fprintf(masscan->echo, "output-filename-ssl-keys = %s\n",
              masscan->output.filename_ssl_keys);
    }
    return CONF_OK;
  }

  strcpy_s(masscan->output.filename_ssl_keys,
           sizeof(masscan->output.filename_ssl_keys), value);
  return CONF_OK;
}

static void CLEANUP_output_filename_ssl_keys(struct Masscan *masscan,
                                             const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_output_format(struct Masscan *masscan, const char *name,
                             const char *value) {
  enum OutputFormat x = 0;
  UNUSEDPARM(name);

  if (masscan->echo) {
    FILE *fp = masscan->echo;
    ipaddress_formatted_t fmt;
    switch (masscan->output.format) {
    case Output_Default:
      if (masscan->echo_all)
        fprintf(fp, "output-format = interactive\n");
      break;
    case Output_Interactive:
      fprintf(fp, "output-format = interactive\n");
      break;
    case Output_List:
      fprintf(fp, "output-format = list\n");
      break;
    case Output_Unicornscan:
      fprintf(fp, "output-format = unicornscan\n");
      break;
    case Output_XML:
      fprintf(fp, "output-format = xml\n");
      break;
    case Output_Binary:
      fprintf(fp, "output-format = binary\n");
      break;
    case Output_Grepable:
      fprintf(fp, "output-format = grepable\n");
      break;
    case Output_JSON:
      fprintf(fp, "output-format = json\n");
      break;
    case Output_NDJSON:
      fprintf(fp, "output-format = ndjson\n");
      break;
    case Output_Certs:
      fprintf(fp, "output-format = certs\n");
      break;
    case Output_None:
      fprintf(fp, "output-format = none\n");
      break;
    case Output_Hostonly:
      fprintf(fp, "output-format = hostonly\n");
      break;
    case Output_Redis:
      ipaddress_fmt(&fmt, &masscan->redis.ip);
      fprintf(fp, "output-format = redis\n");
      fprintf(fp, "redis = %s %u\n", fmt.string, masscan->redis.port);
      break;
    default:
      fprintf(fp, "output-format = unknown(%d)\n", masscan->output.format);
      break;
    }
    return CONF_OK;
  }

  if (EQUALS("unknown(0)", value))
    x = Output_Interactive;
  else if (EQUALS("interactive", value))
    x = Output_Interactive;
  else if (EQUALS("list", value))
    x = Output_List;
  else if (EQUALS("unicornscan", value))
    x = Output_Unicornscan;
  else if (EQUALS("xml", value))
    x = Output_XML;
  else if (EQUALS("binary", value))
    x = Output_Binary;
  else if (EQUALS("greppable", value))
    x = Output_Grepable;
  else if (EQUALS("grepable", value))
    x = Output_Grepable;
  else if (EQUALS("json", value))
    x = Output_JSON;
  else if (EQUALS("ndjson", value))
    x = Output_NDJSON;
  else if (EQUALS("certs", value))
    x = Output_Certs;
  else if (EQUALS("none", value))
    x = Output_None;
  else if (EQUALS("redis", value))
    x = Output_Redis;
  else if (EQUALS("hostonly", value))
    x = Output_Hostonly;
  else {
    LOG(LEVEL_ERROR, "FAIL: unknown output-format: %s\n", value);
    LOG(LEVEL_ERROR, "  hint: 'binary', 'xml', 'grepable', ...\n");
    return CONF_ERR;
  }
  masscan->output.format = x;
  return CONF_OK;
}

static void CLEANUP_output_format(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_output_noshow(struct Masscan *masscan, const char *name,
                             const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->echo_all) {
      fprintf(masscan->echo, "output-noshow = %s%s%s\n",
              (!masscan->output.is_show_open) ? "open," : "",
              (!masscan->output.is_show_closed) ? "closed," : "",
              (!masscan->output.is_show_host) ? "host," : "");
    }
    return CONF_OK;
  }

  for (;;) {
    const char *val2 = value;
    size_t val2_len = INDEX_OF(val2, ',');
    if (val2_len == 0) {
      break;
    }
    if (EQUALSx("open", val2, val2_len)) {
      masscan->output.is_show_open = 0;
    } else if (EQUALSx("closed", val2, val2_len) ||
               EQUALSx("close", val2, val2_len)) {
      masscan->output.is_show_closed = 0;
    } else if (EQUALSx("host", val2, val2_len)) {
      masscan->output.is_show_host = 0;
    } else if (EQUALSx("all", val2, val2_len)) {
      masscan->output.is_show_open = 0;
      masscan->output.is_show_host = 0;
      masscan->output.is_show_closed = 0;
    } else {
      LOG(LEVEL_ERROR, "FAIL: unknown 'noshow' spec: %.*s\n",
          (unsigned)val2_len, val2);
      return CONF_ERR;
    }
    value += val2_len;
    while (*value == ',') {
      value++;
    }
  }
  return CONF_OK;
}

static void CLEANUP_output_noshow(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_output_show(struct Masscan *masscan, const char *name,
                           const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->echo_all) {
      fprintf(masscan->echo, "output-show = %s%s%s\n",
              masscan->output.is_show_open ? "open," : "",
              masscan->output.is_show_closed ? "closed," : "",
              masscan->output.is_show_host ? "host," : "");
    }
    return CONF_OK;
  }

  for (;;) {
    const char *val2 = value;
    size_t val2_len = INDEX_OF(val2, ',');
    if (val2_len == 0)
      break;
    if (EQUALSx("open", val2, val2_len))
      masscan->output.is_show_open = 1;
    else if (EQUALSx("closed", val2, val2_len) ||
             EQUALSx("close", val2, val2_len))
      masscan->output.is_show_closed = 1;
    else if (EQUALSx("host", val2, val2_len))
      masscan->output.is_show_host = 1;
    else if (EQUALSx("all", val2, val2_len)) {
      masscan->output.is_show_open = 1;
      masscan->output.is_show_host = 1;
      masscan->output.is_show_closed = 1;
    } else {
      LOG(LEVEL_ERROR, "FAIL: unknown 'show' spec: %.*s\n", (unsigned)val2_len,
          val2);
      return CONF_ERR;
    }
    value += val2_len;
    while (*value == ',')
      value++;
  }
  return CONF_OK;
}

static void CLEANUP_output_show(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_output_show_open(struct Masscan *masscan, const char *name,
                                const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  /* "open" "open-only" */
  masscan->output.is_show_open = 1;
  masscan->output.is_show_closed = 0;
  masscan->output.is_show_host = 0;
  return CONF_OK;
}

static void CLEANUP_output_show_open(struct Masscan *masscan,
                                     const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

/* Specifies a 'libpcap' file where the received packets will be written.
 * This is useful while debugging so that we can see what exactly is
 * going on. It's also an alternate mode for getting output from this
 * program. Instead of relying upon this program's determination of what
 * ports are open or closed, you can instead simply parse this capture
 * file yourself and make your own determination */
static int SET_pcap_filename(struct Masscan *masscan, const char *name,
                             const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->pcap_filename[0])
      fprintf(masscan->echo, "pcap-filename = %s\n", masscan->pcap_filename);
    return CONF_OK;
  }

  if (value) {
    strcpy_s(masscan->pcap_filename, sizeof(masscan->pcap_filename), value);
  }
  return CONF_OK;
}

static void CLEANUP_pcap_filename(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

/* Specifies a 'libpcap' file from which to read packet-payloads. The payloads
 * found in this file will serve as the template for spewing out custom packets.
 * There are other options that can set payloads as well, like "--nmap-payloads"
 * for reading their custom payload file, as well as the various "hello" options
 * for specifying the string sent to the server once a TCP connection has been
 * established. */
static int SET_pcap_payloads(struct Masscan *masscan, const char *name,
                             const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    char *filename = masscan->payloads.pcap_payloads_filename;
    if ((filename && filename[0]) || masscan->echo_all) {
      if (filename) {
        fprintf(masscan->echo, "pcap-payloads = %s\n", filename);
      } else {
        fprintf(masscan->echo, "pcap-payloads = \n");
      }
    }
    return CONF_OK;
  }

  if (masscan->payloads.pcap_payloads_filename) {
    free(masscan->payloads.pcap_payloads_filename);
  }
  masscan->payloads.pcap_payloads_filename = STRDUP(value);
  /* file will be loaded in "masscan_load_database_files()" */
  return CONF_OK;
}

static void CLEANUP_pcap_payloads(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);

  if (masscan->payloads.pcap_payloads_filename) {
    free(masscan->payloads.pcap_payloads_filename);
    masscan->payloads.pcap_payloads_filename = NULL;
  }
  return;
}

static int SET_randomize_hosts(struct Masscan *masscan, const char *name,
                               const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    // fprintf(masscan->echo, "randomize-hosts = true\n");
    return CONF_OK;
  }

  return CONF_OK;
}

static void CLEANUP_randomize_hosts(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_rate(struct Masscan *masscan, const char *name,
                    const char *value) {
  double rate = 0.0;
  double point = 10.0;
  size_t i;

  if (masscan->echo) {
    if (masscan->max_rate * 100000 < (double)ULLONG_MAX &&
        (unsigned long long int)(masscan->max_rate * 100000) % 100000) {
      /* print as floating point number, which is rare */
      fprintf(masscan->echo, "rate = %f\n", masscan->max_rate);
    } else {
      /* pretty print as just an integer, which is what most people
       * expect */
      fprintf(masscan->echo, "rate = %-10.0f\n", masscan->max_rate);
    }
    return CONF_OK;
  }

  if (EQUALS("min-rate", name)) {
    LOG(LEVEL_ERROR,
        "nmap(%s): unsupported, we go as fast as --max-rate allows\n", name);
    return CONF_ERR;
  }

  for (i = 0; value[i] && value[i] != '.'; i++) {
    char c = value[i];
    if (c < '0' || '9' < c) {
      LOG(LEVEL_ERROR, "CONF: non-digit in rate spec: %s=%s\n", name, value);
      return CONF_ERR;
    }
    rate = rate * 10.0 + (c - '0');
  }

  if (value[i] == '.') {
    i++;
    while (value[i]) {
      char c = value[i];
      if (c < '0' || '9' < c) {
        LOG(LEVEL_ERROR, "CONF: non-digit in rate spec: %s=%s\n", name, value);
        return CONF_ERR;
      }
      rate += (c - '0') / point;
      point *= 10.0;
      value++;
    }
  }
  masscan->max_rate = rate;
  return CONF_OK;
}

static void CLEANUP_rate(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_tranquility(struct Masscan *masscan, const char *name,
                           const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->is_tranquility) {
      fprintf(masscan->echo, "tranquility = true\n");
    }
    return CONF_OK;
  }
  masscan->is_tranquility = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_tranquility(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_resume_count(struct Masscan *masscan, const char *name,
                            const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->resume.count || masscan->echo_all) {
      fprintf(masscan->echo, "resume-count = %" PRIu64 "\n",
              masscan->resume.count);
    }
    return CONF_OK;
  }

  masscan->resume.count = parseInt(value);
  return CONF_OK;
}

static void CLEANUP_resume_count(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_resume_index(struct Masscan *masscan, const char *name,
                            const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->resume.index || masscan->echo_all) {
      fprintf(masscan->echo, "\n# resume information\n");
      fprintf(masscan->echo, "resume-index = %" PRIu64 "\n",
              masscan->resume.index);
    }
    return 0;
  }

  masscan->resume.index = parseInt(value);
  return CONF_OK;
}

static void CLEANUP_resume_index(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_retries(struct Masscan *masscan, const char *name,
                       const char *value) {
  uint64_t x;
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->retries || masscan->echo_all) {
      fprintf(masscan->echo, "retries = %u\n", masscan->retries);
    }
    return CONF_OK;
  }

  x = strtoul(value, 0, 0);
  if (x >= 1000) {
    LOG(LEVEL_ERROR, "FAIL: retries=<n>: expected number less than 1000\n");
    return CONF_ERR;
  }
  masscan->retries = (unsigned)x;
  return CONF_OK;
}

static void CLEANUP_retries(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_rotate_time(struct Masscan *masscan, const char *name,
                           const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->output.rotate.timeout || masscan->echo_all) {
      fprintf(masscan->echo, "rotate = %" PRIuPTR "\n",
              (size_t)masscan->output.rotate.timeout);
    }
    return CONF_OK;
  }

  masscan->output.rotate.timeout = parse_time(value);
  return CONF_OK;
}

static void CLEANUP_rotate_time(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_rotate_directory(struct Masscan *masscan, const char *name,
                                const char *value) {
  char *p;
  size_t lenght_p;
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (memcmp(masscan->output.rotate.directory, ".", 2) != 0 ||
        masscan->echo_all) {
      fprintf(masscan->echo, "rotate-dir = %s\n",
              masscan->output.rotate.directory);
    }
    return CONF_OK;
  }

  strcpy_s(masscan->output.rotate.directory,
           sizeof(masscan->output.rotate.directory), value);
  /* strip trailing slashes */
  p = masscan->output.rotate.directory;
  lenght_p = strlen(p);
  while (*p && (p[lenght_p - 1] == '/' || p[lenght_p - 1] == '\\')) {
    p[lenght_p - 1] = '\0';
    lenght_p--;
  }

  return CONF_OK;
}

static void CLEANUP_rotate_directory(struct Masscan *masscan,
                                     const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_rotate_offset(struct Masscan *masscan, const char *name,
                             const char *value) {
  UNUSEDPARM(name);

  /* Time offset, otherwise output files are aligned to nearest time
   * interval, e.g. at the start of the hour for "hourly" */
  if (masscan->echo) {
    if (masscan->output.rotate.offset || masscan->echo_all) {
      fprintf(masscan->echo, "rotate-offset = %" PRIuPTR "\n",
              (size_t)masscan->output.rotate.offset);
    }
    return CONF_OK;
  }

  masscan->output.rotate.offset = parse_time(value);
  return CONF_OK;
}

static void CLEANUP_rotate_offset(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_rotate_filesize(struct Masscan *masscan, const char *name,
                               const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->output.rotate.filesize || masscan->echo_all) {
      fprintf(masscan->echo, "rotate-size = %" PRIu64 "\n",
              masscan->output.rotate.filesize);
    }
    return CONF_OK;
  }

  masscan->output.rotate.filesize = parseSize(value);
  return CONF_OK;
}

static void CLEANUP_rotate_filesize(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_script(struct Masscan *masscan, const char *name,
                      const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    char *script_name = masscan->scripting.name;
    if ((script_name && script_name[0]) || masscan->echo_all) {
      if (script_name) {
        fprintf(masscan->echo, "script = %s\n", script_name);
      } else {
        fprintf(masscan->echo, "script = \n");
      }
    }
    return CONF_OK;
  }

  if (value && value[0]) {
    masscan->is_scripting = true;
  } else {
    masscan->is_scripting = false;
  }

  if (masscan->scripting.name) {
    free(masscan->scripting.name);
  }
  masscan->scripting.name = STRDUP(value);
  return CONF_OK;
}

static void CLEANUP_script(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);

  if (masscan->scripting.name) {
    free(masscan->scripting.name);
    masscan->scripting.name = NULL;
  }
  return;
}

static int SET_seed(struct Masscan *masscan, const char *name,
                    const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    fprintf(masscan->echo, "seed = %" PRIu64 "\n", masscan->seed);
    return CONF_OK;
  }

  if (EQUALS("time", value)) {
    masscan->seed = time(0);
  } else {
    masscan->seed = parseInt(value);
  }
  return CONF_OK;
}

static void CLEANUP_seed(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_space(struct Masscan *masscan, const char *name,
                     const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);
  if (masscan->echo) {
    fprintf(masscan->echo, "\n");
    return CONF_OK;
  }
  return CONF_OK;
}

static void CLEANUP_space(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_shard(struct Masscan *masscan, const char *name,
                     const char *value) {
  size_t one = 0;
  size_t of = 0;
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->shard.one > 0 || masscan->echo_all) {
      fprintf(masscan->echo, "shard = %" PRIuPTR "/%" PRIuPTR "\n",
              masscan->shard.one, masscan->shard.of);
    }
    return CONF_OK;
  }
  while (isdigit((int)(*value))) {
    one = one * 10 + (*(value++)) - '0';
  }
  while (ispunct((int)(*value))) {
    value++;
  }
  while (isdigit((int)(*value))) {
    of = of * 10 + (*(value++)) - '0';
  }

  if (one < 1) {
    LOG(LEVEL_ERROR, "FAIL: shard index can't be zero\n");
    LOG(LEVEL_ERROR, "hint   it goes like 1/4 2/4 3/4 4/4\n");
    return CONF_ERR;
  }
  if (one > of) {
    LOG(LEVEL_ERROR, "FAIL: shard spec is wrong\n");
    LOG(LEVEL_ERROR, "hint   it goes like 1/4 2/4 3/4 4/4\n");
    return CONF_ERR;
  }
  masscan->shard.one = one;
  masscan->shard.of = of;
  return CONF_OK;
}

static void CLEANUP_shard(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_num_handle_threads(struct Masscan *masscan, const char *name,
                                  const char *value) {
  size_t count;
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->recv_handle_thread_count != 1) {
      fprintf(masscan->echo, "num-handle-threads = %" PRIuPTR "\n",
              masscan->recv_handle_thread_count);
    }
    return CONF_OK;
  }

  count = (size_t)parseInt(value);
  if (count > MAX_THREAD_HANDLE_RECV_COUNT) {
    LOG(LEVEL_ERROR, "%s: num-handle-threads\n", value);
    return CONF_ERR;
  }

  masscan->recv_handle_thread_count = count;
  return CONF_OK;
}

static void CLEANUP_num_handle_threads(struct Masscan *masscan,
                                       const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_output_stylesheet(struct Masscan *masscan, const char *name,
                                 const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->output.stylesheet[0] || masscan->echo_all) {
      fprintf(masscan->echo, "stylesheet = %s\n", masscan->output.stylesheet);
    }
    return CONF_OK;
  }

  if (masscan->output.format == Output_Default) {
    masscan->output.format = Output_XML;
  }
  strcpy_s(masscan->output.stylesheet, sizeof(masscan->output.stylesheet),
           value);
  return CONF_OK;
}

static void CLEANUP_output_stylesheet(struct Masscan *masscan,
                                      const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_config(struct Masscan *masscan, const char *name,
                      const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  masscan_read_config_file(masscan, value);
  return CONF_OK;
}

static void CLEANUP_config(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_adapter(struct Masscan *masscan, const char *name,
                       const char *value) {
  size_t index;
  UNUSEDPARM(name);

  if (masscan->echo) {
    size_t iter_nic_index = 0;
    for (iter_nic_index = 0; iter_nic_index < max(masscan->nic_count, 1);
         iter_nic_index++) {
      char idx_str[64] = "\0";
      if (masscan->nic_count > 1) {
        /* If we have only one adapter, then don't print the array indexes.
         * Otherwise, we need to print the array indexes to distinguish
         * the NICs from each other */
        sprintf_s(idx_str, sizeof(idx_str), "[%" PRIuPTR "]", iter_nic_index);
      }
      if (masscan->nic[iter_nic_index].ifname[0]) {
        fprintf(masscan->echo, "adapter%s = %s\n", idx_str,
                masscan->nic[iter_nic_index].ifname);
      }
    }
    return CONF_OK;
  }

  index = ARRAY(name);
  if (index >= ARRAY_SIZE(masscan->nic)) {
    LOG(LEVEL_ERROR, "%s: bad index\n", name);
    return CONF_ERR;
  }

  if (masscan->nic[index].ifname[0]) {
    LOG(LEVEL_WARNING, "CONF: overwriting \"adapter=%s\"\n",
        masscan->nic[index].ifname);
  }
  if (masscan->nic_count < index + 1) {
    masscan->nic_count = index + 1;
  }
  sprintf_s(masscan->nic[index].ifname, sizeof(masscan->nic[index].ifname),
            "%s", value);

  return CONF_OK;
}

static void CLEANUP_adapter(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_adapter_ip(struct Masscan *masscan, const char *name,
                          const char *value) {
  /* Send packets FROM this IP address */
  struct Range range;
  struct Range6 range6;
  size_t index;
  enum RangeParseResult err;
  UNUSEDPARM(name);

  if (masscan->echo) {
    size_t iter_nic_index = 0;
    for (iter_nic_index = 0; iter_nic_index < max(masscan->nic_count, 1);
         iter_nic_index++) {
      char idx_str[64] = "\0";
      if (masscan->nic_count > 1) {
        /* If we have only one adapter, then don't print the array indexes.
         * Otherwise, we need to print the array indexes to distinguish
         * the NICs from each other */
        sprintf_s(idx_str, sizeof(idx_str), "[%" PRIuPTR "]", iter_nic_index);
      }

      if (masscan->nic[iter_nic_index].src.ipv4.first == 0 &&
          masscan->nic[iter_nic_index].src.ipv4.last == 0) {
        // pass
      } else if (masscan->nic[iter_nic_index].src.ipv4.first ==
                 masscan->nic[iter_nic_index].src.ipv4.last) {
        /* FIX 495.1 for issue #495: Single adapter-ip is not saved at all
         *
         * The else case handles a simple invocation of one adapter-ip:
         *
         * 1. masscan ... --adapter-ip 1.2.3.1 ...   [BROKEN]
         *
         * This looks like it was just copy pasta/typo. If the first ip is the
         * same as the last ip, it is a single adapter-ip
         *
         * This never worked as it was before so paused.conf would never save
         * the adapter-ip as it fell through this if/else if into nowhere. It
         * probably went undetected because in simple environments and/or in
         * simple scans, masscan is able to intelligently determine the
         * adapter-ip and only advanced usage requires overriding the chosen
         * value. In addition to that, it is probably relatively uncommon to
         * interrupt a scan as not many users are doing multi-hour / multi-day
         * scans, having them paused and then resuming them (apparently) */
        ipaddress_formatted_t fmt;
        ipv4address_fmt(&fmt, &masscan->nic[iter_nic_index].src.ipv4.first);
        fprintf(masscan->echo, "adapter-ip%s = %s\n", idx_str, fmt.string);
      } else if (masscan->nic[iter_nic_index].src.ipv4.first <
                 masscan->nic[iter_nic_index].src.ipv4.last) {
        /* FIX 495.2 for issue #495: Ranges of size two don't print. When 495.1
         * is added, ranges of size two print as only the first value in the
         * range Before 495.1, they didn't print at all, so this is not a bug
         * that is introduced by 495.1, just noticed while applying that fix
         *
         * The first if case here is for handling when adapter-ip is a range
         *
         * Examples of the multiple/range case:
         *
         * 1. masscan ... --adapter-ip 1.2.3.1-1.2.3.2 ...   [BROKEN]
         * 2. masscan ... --adapter-ip 1.2.3.1-1.2.3.4 ...   [OK]
         *
         * If the range spans exactly two adapter-ips, it will not hit the range
         * printing logic case here because of an off-by-one
         *
         * Changing it from < to <= fixes that issue and both of the above cases
         * now print the correct range as expected */
        ipaddress_formatted_t fmt1;
        ipaddress_formatted_t fmt2;
        ipv4address_fmt(&fmt1, &masscan->nic[iter_nic_index].src.ipv4.first);
        ipv4address_fmt(&fmt2, &masscan->nic[iter_nic_index].src.ipv4.last);
        fprintf(masscan->echo, "adapter-ip%s = %s-%s\n", idx_str, fmt1.string,
                fmt2.string);
      }

      if (masscan->nic[iter_nic_index].src.ipv6.range == 0) {
        // pass
      } else if (ipv6address_is_lessthan(
                     &masscan->nic[iter_nic_index].src.ipv6.first,
                     &masscan->nic[iter_nic_index].src.ipv6.last)) {
        ipaddress_formatted_t fmt1;
        ipaddress_formatted_t fmt2;
        ipv6address_fmt(&fmt1, &masscan->nic[iter_nic_index].src.ipv6.first);
        ipv6address_fmt(&fmt2, &masscan->nic[iter_nic_index].src.ipv6.last);
        fprintf(masscan->echo, "adapter-ip%s = %s-%s\n", idx_str, fmt1.string,
                fmt2.string);
      } else {
        ipaddress_formatted_t fmt;
        ipv6address_fmt(&fmt, &masscan->nic[iter_nic_index].src.ipv6.first);
        fprintf(masscan->echo, "adapter-ip%s = %s\n", idx_str, fmt.string);
      }
    }
    return CONF_OK;
  }

  index = ARRAY(name);
  if (index >= ARRAY_SIZE(masscan->nic)) {
    LOG(LEVEL_ERROR, "%s: bad index\n", name);
    return CONF_ERR;
  }

  err = massip_parse_range(value, NULL, 0, &range, &range6);
  switch (err) {
  case Ipv4_Address:
    /* If more than one IP address given, make the range is
     * an even power of two (1, 2, 4, 8, 16, ...) */
    if (!is_power_of_two((uint64_t)range.end - range.begin + 1)) {
      LOG(LEVEL_ERROR, "FAIL: range must be even power of two: %s=%s\n", name,
          value);
      return CONF_ERR;
    }
    masscan->nic[index].src.ipv4.first = range.begin;
    masscan->nic[index].src.ipv4.last = range.end;
    masscan->nic[index].src.ipv4.range = range.end - range.begin + 1;
    break;
  case Ipv6_Address:
    masscan->nic[index].src.ipv6.first = range6.begin;
    masscan->nic[index].src.ipv6.last = range6.end;
    masscan->nic[index].src.ipv6.range =
        1; /* TODO: add support for more than one source */
    break;
  default:
    LOG(LEVEL_ERROR, "FAIL: bad source IP address: %s=%s\n", name, value);
    LOG(LEVEL_ERROR, "hint   addresses look like \"192.168.1.23\" or "
                     "\"2001:db8:1::1ce9\".\n");
    return CONF_ERR;
  }

  return CONF_OK;
}

static void CLEANUP_adapter_ip(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_adapter_port(struct Masscan *masscan, const char *name,
                            const char *value) {
  unsigned is_error = 0;
  struct RangeList ports = {0};
  size_t index;
  UNUSEDPARM(name);

  if (masscan->echo) {
    size_t iter_nic_index = 0;
    for (iter_nic_index = 0; iter_nic_index < max(masscan->nic_count, 1);
         iter_nic_index++) {
      char idx_str[64] = "\0";
      char proto[3] = "\0";
      unsigned int first = masscan->nic[iter_nic_index].src.port.first;
      unsigned int last = masscan->nic[iter_nic_index].src.port.last;

      if (masscan->nic_count > 1) {
        /* If we have only one adapter, then don't print the array indexes.
         * Otherwise, we need to print the array indexes to distinguish
         * the NICs from each other */
        sprintf_s(idx_str, sizeof(idx_str), "[%" PRIuPTR "]", iter_nic_index);
      }

      if (first >= Templ_Oproto && last <= Templ_Oproto_last) {
        sprintf_s(proto, sizeof(proto), "O:");
        first -= Templ_Oproto;
        last -= Templ_Oproto;
      } else if (first >= Templ_ICMP && last <= Templ_ICMP_last) {
        sprintf_s(proto, sizeof(proto), "I:");
        first -= Templ_ICMP;
        last -= Templ_ICMP;
      } else if (first >= Templ_SCTP && last <= Templ_SCTP_last) {
        sprintf_s(proto, sizeof(proto), "S:");
        first -= Templ_SCTP;
        last -= Templ_SCTP;
      } else if (first >= Templ_UDP && last <= Templ_UDP_last) {
        sprintf_s(proto, sizeof(proto), "U:");
        first -= Templ_UDP;
        last -= Templ_UDP;
      }

      if (masscan->nic[iter_nic_index].src.port.range == 0) {
        // pass
      } else if (first == last) {
        fprintf(masscan->echo, "adapter-port%s = %s%u\n", idx_str, proto,
                first);
      } else if (first < last) {
        fprintf(masscan->echo, "adapter-port%s = %s%u-%u\n", idx_str, proto,
                first, last);
      }
    }
    return CONF_OK;
  }

  index = ARRAY(name);
  if (index >= ARRAY_SIZE(masscan->nic)) {
    LOG(LEVEL_ERROR, "%s: bad index\n", name);
    return CONF_ERR;
  }
  rangelist_parse_ports(&ports, value, &is_error, 0);

  /* Check if there was an error in parsing */
  if (is_error) {
    LOG(LEVEL_ERROR, "FAIL: bad source port specification: %s\n", name);
    rangelist_remove_all(&ports);
    return CONF_ERR;
  }
  /* Only allow one range of ports */
  if (ports.count != 1) {
    LOG(LEVEL_ERROR,
        "FAIL: only one '%s' range may be specified, found %" PRIuPTR
        " ranges\n",
        name, ports.count);
    rangelist_remove_all(&ports);
    return CONF_ERR;
  }
  /* verify range is even power of 2 (1, 2, 4, 8, 16, ...) */
  if (!is_power_of_two((uint64_t)ports.list[0].end -
                       (uint64_t)ports.list[0].begin + 1)) {
    LOG(LEVEL_ERROR,
        "FAIL: source port range must be even power of two: %s=%s\n", name,
        value);
    rangelist_remove_all(&ports);
    return CONF_ERR;
  }

  masscan->nic[index].src.port.first = ports.list[0].begin;
  masscan->nic[index].src.port.last = ports.list[0].end;
  masscan->nic[index].src.port.range =
      ports.list[0].end - ports.list[0].begin + 1;
  rangelist_remove_all(&ports);
  return CONF_OK;
}

static void CLEANUP_adapter_port(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_adapter_mac(struct Masscan *masscan, const char *name,
                           const char *value) {
  /* Send packets FROM this MAC address */
  macaddress_t source_mac;
  size_t index;
  int err;
  UNUSEDPARM(name);

  if (masscan->echo) {
    size_t iter_nic_index = 0;
    for (iter_nic_index = 0; iter_nic_index < max(masscan->nic_count, 1);
         iter_nic_index++) {
      char idx_str[64] = "\0";
      if (masscan->nic_count > 1) {
        /* If we have only one adapter, then don't print the array indexes.
         * Otherwise, we need to print the array indexes to distinguish
         * the NICs from each other */
        sprintf_s(idx_str, sizeof(idx_str), "[%" PRIuPTR "]", iter_nic_index);
      }
      if (masscan->nic[iter_nic_index].my_mac_count) {
        ipaddress_formatted_t fmt;
        macaddress_fmt(&fmt, &masscan->nic[iter_nic_index].source_mac);
        fprintf(masscan->echo, "adapter-mac%s = %s\n", idx_str, fmt.string);
      }
    }
    return CONF_OK;
  }

  index = ARRAY(name);
  if (index >= ARRAY_SIZE(masscan->nic)) {
    LOG(LEVEL_ERROR, "%s: bad index\n", name);
    return CONF_ERR;
  }
  err = parse_mac_address(value, &source_mac);
  if (err) {
    LOG(LEVEL_WARNING, "[-] CONF: bad MAC address: %s = %s\n", name, value);
    return CONF_ERR;
  }
  /* Check for duplicates */
  if (macaddress_is_equal(&masscan->nic[index].source_mac, &source_mac)) {
    /* suppresses warning message about duplicate MAC addresses if
     * they are in fact the same */
    return CONF_OK;
  }
  /* Warn if we are overwriting a Mac address */
  if (masscan->nic[index].my_mac_count != 0) {
    ipaddress_formatted_t fmt1;
    ipaddress_formatted_t fmt2;
    macaddress_fmt(&fmt1, &masscan->nic[index].source_mac);
    macaddress_fmt(&fmt2, &source_mac);
    LOG(LEVEL_WARNING, "[-] WARNING: overwriting MAC address, was %s, now %s\n",
        fmt1.string, fmt2.string);
  }
  masscan->nic[index].source_mac = source_mac;
  masscan->nic[index].my_mac_count = 1;
  return CONF_OK;
}

static void CLEANUP_adapter_mac(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_router_mac(struct Masscan *masscan, const char *name,
                          const char *value) {
  macaddress_t router_mac;
  size_t index;
  int err;
  UNUSEDPARM(name);

  if (masscan->echo) {
    size_t iter_nic_index = 0;
    for (iter_nic_index = 0; iter_nic_index < max(masscan->nic_count, 1);
         iter_nic_index++) {
      char idx_str[64] = "\0";
      if (masscan->nic_count > 1) {
        /* If we have only one adapter, then don't print the array indexes.
         * Otherwise, we need to print the array indexes to distinguish
         * the NICs from each other */
        sprintf_s(idx_str, sizeof(idx_str), "[%" PRIuPTR "]", iter_nic_index);
      }

      if (!macaddress_is_zero(&masscan->nic[iter_nic_index].router_mac_ipv4)) {
        ipaddress_formatted_t fmt;
        macaddress_fmt(&fmt, &masscan->nic[iter_nic_index].router_mac_ipv4);
        fprintf(masscan->echo, "router-mac-ipv4%s = %s\n", idx_str, fmt.string);
      }
      if (!macaddress_is_zero(&masscan->nic[iter_nic_index].router_mac_ipv6)) {
        ipaddress_formatted_t fmt;
        macaddress_fmt(&fmt, &masscan->nic[iter_nic_index].router_mac_ipv6);
        fprintf(masscan->echo, "router-mac-ipv6%s = %s\n", idx_str, fmt.string);
      }
    }
    return CONF_OK;
  }

  index = ARRAY(name);
  if (index >= ARRAY_SIZE(masscan->nic)) {
    LOG(LEVEL_ERROR, "%s: bad index\n", name);
    return CONF_ERR;
  }

  err = parse_mac_address(value, &router_mac);
  if (err) {
    LOG(LEVEL_ERROR, "[-] CONF: bad MAC address: %s = %s\n", name, value);
    return CONF_ERR;
  }

  masscan->nic[index].router_mac_ipv4 = router_mac;
  masscan->nic[index].router_mac_ipv6 = router_mac;
  return CONF_OK;
}

static void CLEANUP_router_mac(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_router_mac_ipv4(struct Masscan *masscan, const char *name,
                               const char *value) {
  macaddress_t router_mac;
  size_t index;
  int err;
  UNUSEDPARM(name);

  if (masscan->echo) {
    // see SET_router_mac
    return CONF_OK;
  }

  index = ARRAY(name);
  if (index >= ARRAY_SIZE(masscan->nic)) {
    LOG(LEVEL_ERROR, "%s: bad index\n", name);
    return CONF_ERR;
  }

  err = parse_mac_address(value, &router_mac);
  if (err) {
    LOG(LEVEL_WARNING, "[-] CONF: bad MAC address: %s = %s\n", name, value);
    return CONF_ERR;
  }

  masscan->nic[index].router_mac_ipv4 = router_mac;
  return CONF_OK;
}

static void CLEANUP_router_mac_ipv4(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_router_mac_ipv6(struct Masscan *masscan, const char *name,
                               const char *value) {
  macaddress_t router_mac;
  size_t index;
  int err;
  UNUSEDPARM(name);

  if (masscan->echo) {
    // see SET_router_mac
    return CONF_OK;
  }

  index = ARRAY(name);
  if (index >= ARRAY_SIZE(masscan->nic)) {
    LOG(LEVEL_ERROR, "%s: bad index\n", name);
    return CONF_ERR;
  }

  err = parse_mac_address(value, &router_mac);
  if (err) {
    LOG(LEVEL_WARNING, "[-] CONF: bad MAC address: %s = %s\n", name, value);
    return CONF_ERR;
  }

  masscan->nic[index].router_mac_ipv6 = router_mac;
  return CONF_OK;
}

static void CLEANUP_router_mac_ipv6(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_router_ip(struct Masscan *masscan, const char *name,
                         const char *value) {
  /* Send packets FROM this IP address */
  struct Range range, *p_range;
  size_t index;
  UNUSEDPARM(name);

  if (masscan->echo) {
    size_t iter_nic_index = 0;
    for (iter_nic_index = 0; iter_nic_index < max(masscan->nic_count, 1);
         iter_nic_index++) {
      char idx_str[64] = "\0";
      if (masscan->nic_count > 1) {
        /* If we have only one adapter, then don't print the array indexes.
         * Otherwise, we need to print the array indexes to distinguish
         * the NICs from each other */
        sprintf_s(idx_str, sizeof(idx_str), "[%" PRIuPTR "]", iter_nic_index);
      }
      if (masscan->nic[iter_nic_index].router_ip) {
        ipaddress_formatted_t fmt;
        ipv4address_fmt(&fmt, &masscan->nic[iter_nic_index].router_ip);
        fprintf(masscan->echo, "router-ip%s = %s\n", idx_str, fmt.string);
      }
    }
    return CONF_OK;
  }

  index = ARRAY(name);
  if (index >= ARRAY_SIZE(masscan->nic)) {
    LOG(LEVEL_ERROR, "%s: bad index\n", name);
    return CONF_ERR;
  }

  p_range = range_parse_ipv4(value, NULL, 0, &range);
  /* Check for bad format */
  if (p_range == NULL || range.begin != range.end) {
    LOG(LEVEL_ERROR, "FAIL: bad source IPv4 address: %s=%s\n", name, value);
    LOG(LEVEL_ERROR, "hint   addresses look like \"19.168.1.23\"\n");
    return CONF_ERR;
  }
  masscan->nic[index].router_ip = range.begin;
  return CONF_OK;
}

static void CLEANUP_router_ip(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_udp_ports(struct Masscan *masscan, const char *name,
                         const char *value) {
  unsigned is_error = 0;

  UNUSEDPARM(name);
  if (masscan->echo) {
    return CONF_OK;
  }

  masscan->scan_type.udp = true;
  rangelist_parse_ports(&masscan->targets.ports, value, &is_error, Templ_UDP);
  if (masscan->op == Operation_Default) {
    masscan->op = Operation_Scan;
  }
  return CONF_OK;
}

static void CLEANUP_udp_ports(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_oprotos(struct Masscan *masscan, const char *name,
                       const char *value) {
  unsigned is_error = 0;
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  masscan->scan_type.oproto = true;
  rangelist_parse_ports(&masscan->targets.ports, value, &is_error,
                        Templ_Oproto);
  if (masscan->op == Operation_Default) {
    masscan->op = Operation_Scan;
  }
  return CONF_OK;
}

static void CLEANUP_oprotos(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_tcp_ports(struct Masscan *masscan, const char *name,
                         const char *value) {
  unsigned is_error = 0;
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  masscan->scan_type.tcp = true;
  rangelist_parse_ports(&masscan->targets.ports, value, &is_error, Templ_TCP);
  if (masscan->op == Operation_Default) {
    masscan->op = Operation_Scan;
  }
  return CONF_OK;
}

static void CLEANUP_tcp_ports(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_ports(struct Masscan *masscan, const char *name,
                     const char *value) {
  unsigned err = 0;
  unsigned defaultrange = Templ_TCP;
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (masscan->scan_type.udp) {
    defaultrange = Templ_UDP;
  } else if (masscan->scan_type.sctp) {
    defaultrange = Templ_SCTP;
  }

  err = massip_add_port_string(&masscan->targets, value, defaultrange);
  if (err) {
    LOG(LEVEL_ERROR, "[-] FAIL: bad target port: %s\n", value);
    LOG(LEVEL_ERROR, "    Hint: a port is a number [0..65535]\n");
    return CONF_OK;
  }

  if (masscan->op == Operation_Default) {
    masscan->op = Operation_Scan;
  }
  return CONF_OK;
}

static void CLEANUP_ports(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_banner_types(struct Masscan *masscan, const char *name,
                            const char *value) {
  enum ApplicationProtocol app;
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  app = masscan_string_to_app(value);
  if (app) {
    rangelist_add_range(&masscan->banner_types, (unsigned int)app,
                        (unsigned int)app);
    rangelist_sort(&masscan->banner_types);
  } else {
    LOG(LEVEL_ERROR, "FAIL: bad banner app: %s\n", value);
    return CONF_ERR;
  }
  return CONF_OK;
}

static void CLEANUP_banner_types(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_exclude_ports(struct Masscan *masscan, const char *name,
                             const char *value) {
  unsigned defaultrange = Templ_TCP;
  int err;
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (masscan->scan_type.udp) {
    defaultrange = Templ_UDP;
  } else if (masscan->scan_type.sctp) {
    defaultrange = Templ_SCTP;
  }

  err = massip_add_port_string(&masscan->exclude, value, defaultrange);
  if (err) {
    LOG(LEVEL_ERROR, "[-] FAIL: bad exclude port: %s\n", value);
    LOG(LEVEL_ERROR, "    Hint: a port is a number [0..65535]\n");
    return CONF_ERR;
  }
  if (masscan->op == Operation_Default) {
    masscan->op = Operation_Scan;
  }
  return CONF_OK;
}

static void CLEANUP_exclude_ports(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_bpf(struct Masscan *masscan, const char *name,
                   const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->bpf_filter) {
      fprintf(masscan->echo, "bpf = %s\n", masscan->bpf_filter);
    }
    return CONF_OK;
  }

  if (masscan->bpf_filter) {
    free(masscan->bpf_filter);
  }
  masscan->bpf_filter = STRDUP(value);
  return CONF_OK;
}

static void CLEANUP_bpf(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);

  if (masscan->bpf_filter) {
    free(masscan->bpf_filter);
    masscan->bpf_filter = NULL;
  }
  return;
}

static int SET_ping(struct Masscan *masscan, const char *name,
                    const char *value) {
  /* Add ICMP ping request */
  struct Range range;
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->scan_type.ping) {
      fprintf(masscan->echo, "ping = true\n");
    }
    return CONF_OK;
  }

  if (parseBoolean(value)) {
    range.begin = Templ_ICMP_echo;
    range.end = Templ_ICMP_echo;
    rangelist_add_range(&masscan->targets.ports, range.begin, range.end);
    rangelist_sort(&masscan->targets.ports);
    masscan->scan_type.ping = true;
  }
  LOG(LEVEL_DEBUG_3, "--ping\n");
  return CONF_OK;
}

static void CLEANUP_ping(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_range(struct Masscan *masscan, const char *name,
                     const char *value) {
  int err;

  UNUSEDPARM(name);
  if (masscan->echo) {
    return CONF_OK;
  }

  err = massip_add_target_string(&masscan->targets, value);
  if (err) {
    LOG(LEVEL_WARNING, "ERROR: bad IP address/range: %s\n", value);
    return CONF_ERR;
  }

  if (masscan->op == Operation_Default) {
    masscan->op = Operation_Scan;
  }
  return CONF_OK;
}

static void CLEANUP_range(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_exclude(struct Masscan *masscan, const char *name,
                       const char *value) {
  int err;
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  err = massip_add_target_string(&masscan->exclude, value);
  if (err) {
    LOG(LEVEL_ERROR, "ERROR: bad exclude address/range: %s\n", value);
  }

  if (masscan->op == Operation_Default) {
    masscan->op = Operation_Scan;
  }
  return CONF_OK;
}

static void CLEANUP_exclude(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_badsum(struct Masscan *masscan, const char *name,
                      const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->nmap.badsum) {
      fprintf(masscan->echo, "badsum = true\n");
    }
    return CONF_OK;
  }

  masscan->nmap.badsum = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_badsum(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_test_banner1(struct Masscan *masscan, const char *name,
                            const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (masscan->banner1_test_name) {
    free(masscan->banner1_test_name);
  }
  masscan->banner1_test_name = STRDUP(value);
  masscan->op = Operation_Selftest;
  return CONF_OK;
}

static void CLEANUP_test_banner1(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);

  if (masscan->banner1_test_name) {
    free(masscan->banner1_test_name);
    masscan->banner1_test_name = 0;
  }
  return;
}

static int SET_blackrock_rounds(struct Masscan *masscan, const char *name,
                                const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->blackrock_rounds) {
      fprintf(masscan->echo, "blackrock-rounds = %u\n",
              masscan->blackrock_rounds);
    }
    return CONF_OK;
  }

  masscan->blackrock_rounds = (unsigned)parseInt(value);
  return CONF_OK;
}

static void CLEANUP_blackrock_rounds(struct Masscan *masscan,
                                     const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_connection_timeout(struct Masscan *masscan, const char *name,
                                  const char *value) {
  /* The timeout for banners TCP connections */
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->tcp_connection_timeout) {
      fprintf(masscan->echo, "connection-timeout = %u\n",
              masscan->tcp_connection_timeout);
    }
    return CONF_OK;
  }
  masscan->tcp_connection_timeout = (unsigned)parseInt(value);
  return CONF_OK;
}

static void CLEANUP_connection_timeout(struct Masscan *masscan,
                                       const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_datadir(struct Masscan *masscan, const char *name,
                       const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->nmap.datadir[0]) {
      fprintf(masscan->echo, "datadir = %s\n", masscan->nmap.datadir);
    }
    return CONF_OK;
  }

  strcpy_s(masscan->nmap.datadir, sizeof(masscan->nmap.datadir), value);
  return CONF_OK;
}

static void CLEANUP_datadir(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_data_length(struct Masscan *masscan, const char *name,
                           const char *value) {
  unsigned x;
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->nmap.data_length) {
      fprintf(masscan->echo, "data-length = %u\n", masscan->nmap.data_length);
    }
    return CONF_OK;
  }

  x = (unsigned)strtoul(value, 0, 0);
  if (x >= ETH_DATA_LEN - 40) {
    LOG(LEVEL_WARNING, "error: %s=<n>: expected number less than 1500\n", name);
    return CONF_WARN;
  } else {
    masscan->nmap.data_length = x;
  }
  return CONF_OK;
}

static void CLEANUP_data_length(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_debug(struct Masscan *masscan, const char *name,
                     const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (EQUALS("if", value)) {
    masscan->op = Operation_DebugIF;
  } else {
    LOG(LEVEL_ERROR, "CONF: %s bad type: %s\n", name, value);
    return CONF_ERR;
  }
  return CONF_OK;
}

static void CLEANUP_debug(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_dns_servers(struct Masscan *masscan, const char *name,
                           const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): unsupported: DNS lookups too synchronous\n",
      name);
  return CONF_ERR;
}

static void CLEANUP_dns_servers(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_echo(struct Masscan *masscan, const char *name,
                    const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (EQUALS("echo-all", name)) {
    if (parseBoolean(value)) {
      masscan->op = Operation_EchoAll;
    }
  } else if (EQUALS("echo", name)) {
    if (parseBoolean(value)) {
      masscan->op = Operation_Echo;
    }
  } else {
    LOG(LEVEL_ERROR, "CONF: %s bad type: %s\n", name, value);
    return CONF_ERR;
  }

  return CONF_OK;
}

static void CLEANUP_echo(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_excludefile(struct Masscan *masscan, const char *name,
                           const char *value) {
  size_t count1, count2;
  int err;
  const char *filename;
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  count1 = masscan->exclude.ipv4.count;
  filename = value;

  LOG(LEVEL_INFO, "EXCLUDING: %s\n", value);
  err = massip_parse_file(&masscan->exclude, filename);
  if (err) {
    LOG(LEVEL_ERROR, "[-] FAIL: error reading from exclude file\n");
    return CONF_ERR;
  }

  /* Detect if this file has made any change, otherwise don't print
   * a message */
  count2 = masscan->exclude.ipv4.count;
  if (count2 > count1) {
    LOG(LEVEL_WARNING, "%s: excluding %" PRIu64 " ranges from file\n", value,
        count2 - count1);
  }
  return CONF_OK;
}

static void CLEANUP_excludefile(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_heartbleed(struct Masscan *masscan, const char *name,
                          const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->is_heartbleed) {
      fprintf(masscan->echo, "heartbleed = true\n");
    }
    return CONF_OK;
  }

  if (parseBoolean(value)) {
    masscan->is_heartbleed = parseBoolean(value);
    masscan_set_parameter(masscan, "no-capture", "cert");
    masscan_set_parameter(masscan, "no-capture", "heartbleed");
    masscan_set_parameter(masscan, "banners", "true");
  }
  return CONF_OK;
}

static void CLEANUP_heartbleed(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_ticketbleed(struct Masscan *masscan, const char *name,
                           const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->is_ticketbleed) {
      fprintf(masscan->echo, "ticketbleed = true\n");
    }
    return CONF_OK;
  }

  if (parseBoolean(value)) {
    masscan->is_ticketbleed = parseBoolean(value);
    masscan_set_parameter(masscan, "no-capture", "cert");
    masscan_set_parameter(masscan, "no-capture", "heartbleed");
    masscan_set_parameter(masscan, "banners", "true");
  }
  return CONF_OK;
}

static void CLEANUP_ticketbleed(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_host_timeout(struct Masscan *masscan, const char *name,
                            const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }
  LOG(LEVEL_ERROR,
      "nmap(%s): unsupported: this is an asynchronous tool, so no timeouts\n",
      name);
  return CONF_ERR;
}

static void CLEANUP_host_timeout(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_iflist(struct Masscan *masscan, const char *name,
                      const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }
  if (parseBoolean(value)) {
    masscan->op = Operation_List_Adapters;
  }
  return CONF_OK;
}

static void CLEANUP_iflist(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_includefile(struct Masscan *masscan, const char *name,
                           const char *value) {
  int err;
  const char *filename;
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  filename = value;
  err = massip_parse_file(&masscan->targets, filename);
  if (err) {
    LOG(LEVEL_ERROR, "[-] FAIL: error reading from include file\n");
    return CONF_ERR;
  }
  if (masscan->op == Operation_Default) {
    masscan->op = Operation_Scan;
  }
  return CONF_OK;
}

static void CLEANUP_includefile(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_infinite(struct Masscan *masscan, const char *name,
                        const char *value) {
  UNUSEDPARM(name);
  if (masscan->echo) {
    if (masscan->is_infinite) {
      fprintf(masscan->echo, "infinite = true\n");
    }
    return CONF_OK;
  }

  masscan->is_infinite = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_infinite(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_interactive(struct Masscan *masscan, const char *name,
                           const char *value) {
  UNUSEDPARM(name);
  if (masscan->echo) {
    return CONF_OK;
  }

  if (EQUALS("interactive", name)) {
    masscan->output.is_interactive = parseBoolean(value);
  } else if (EQUALS("nointeractive", name)) {
    masscan->output.is_interactive = !parseBoolean(value);
  } else {
    LOG(LEVEL_ERROR, "unsupported: %s\n", name);
    return CONF_ERR;
  }
  return CONF_OK;
}

static void CLEANUP_interactive(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_status(struct Masscan *masscan, const char *name,
                      const char *value) {
  UNUSEDPARM(name);
  if (masscan->echo) {
    return CONF_OK;
  }

  if (EQUALS("status", name)) {
    masscan->output.is_status_updates = parseBoolean(value);
  } else if (EQUALS("nostatus", name)) {
    masscan->output.is_status_updates = !parseBoolean(value);
  } else {
    LOG(LEVEL_ERROR, "unsupported: %s\n", name);
    return CONF_ERR;
  }
  return CONF_OK;
}

static void CLEANUP_status(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_ip_options(struct Masscan *masscan, const char *name,
                          const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }
  LOG(LEVEL_ERROR, "nmap(%s): unsupported: maybe soon\n", name);
  return CONF_ERR;
}

static void CLEANUP_ip_options(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_log_errors(struct Masscan *masscan, const char *name,
                          const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }
  LOG(LEVEL_ERROR, "nmap(%s): unsupported: maybe soon\n", name);
  return CONF_ERR;
}

static void CLEANUP_log_errors(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_hostgroup(struct Masscan *masscan, const char *name,
                         const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }
  LOG(LEVEL_ERROR, "nmap(%s): unsupported: we randomize all the groups!\n",
      name);
  return CONF_ERR;
}

static void CLEANUP_hostgroup(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_parallelism(struct Masscan *masscan, const char *name,
                           const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }
  LOG(LEVEL_ERROR, "nmap(%s): unsupported: we all the parallel!\n", name);
  return CONF_ERR;
}

static void CLEANUP_parallelism(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_rtt_timeout(struct Masscan *masscan, const char *name,
                           const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }
  LOG(LEVEL_ERROR,
      "nmap(%s): unsupported: we are asynchronous, so no timeouts, no RTT "
      "tracking!\n",
      name);
  return CONF_ERR;
}

static void CLEANUP_rtt_timeout(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_mtu(struct Masscan *masscan, const char *name,
                   const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): fragmentation not yet supported\n", name);
  return CONF_ERR;
}

static void CLEANUP_mtu(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_nmap(struct Masscan *masscan, const char *name,
                    const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (parseBoolean(value)) {
    masscan->op = Operation_NmapHelp;
  }
  return CONF_OK;
}

static void CLEANUP_nmap(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_offline(struct Masscan *masscan, const char *name,
                       const char *value) {
  /* Run in "offline" mode where it thinks it's sending packets, but it's not */
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    if (masscan->is_offline || masscan->echo_all) {
      fprintf(masscan->echo, "offline = %s\n",
              masscan->is_offline ? "true" : "false");
    }
    return CONF_OK;
  }
  masscan->is_offline = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_offline(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_osscan_limit(struct Masscan *masscan, const char *name,
                            const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): OS scanning unsupported\n", name);
  return CONF_ERR;
}

static void CLEANUP_osscan_limit(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_osscan_guess(struct Masscan *masscan, const char *name,
                            const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): OS scanning unsupported\n", name);
  return CONF_ERR;
}

static void CLEANUP_osscan_guess(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_packet_trace(struct Masscan *masscan, const char *name,
                            const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->nmap.packet_trace) {
      fprintf(masscan->echo, "packet-trace = true\n");
    }
    return CONF_OK;
  }

  masscan->nmap.packet_trace = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_packet_trace(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_privileged(struct Masscan *masscan, const char *name,
                          const char *value) {
  UNUSEDPARM(value);
  if (masscan->echo) {
    return CONF_OK;
  }
  LOG(LEVEL_ERROR, "nmap(%s): unsupported\n", name);
  return CONF_ERR;
}

static void CLEANUP_privileged(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_pfring(struct Masscan *masscan, const char *name,
                      const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->is_pfring) {
      fprintf(masscan->echo, "pfring = true\n");
    }
    return CONF_OK;
  }

  masscan->is_pfring = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_pfring(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_port_ratio(struct Masscan *masscan, const char *name,
                          const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): unsupported\n", name);
  return CONF_ERR;
}

static void CLEANUP_port_ratio(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_readrange(struct Masscan *masscan, const char *name,
                         const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (parseBoolean(value)) {
    masscan->op = Operation_ReadRange;
  }
  return CONF_OK;
}

static void CLEANUP_readrange(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_reason(struct Masscan *masscan, const char *name,
                      const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->output.is_reason) {
      fprintf(masscan->echo, "reason = true\n");
    }
    return CONF_OK;
  }

  masscan->output.is_reason = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_reason(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_redis(struct Masscan *masscan, const char *name,
                     const char *value) {
  struct Range range, *p_range;
  size_t offset = 0;
  size_t max_offset;
  unsigned port = 6379;

  UNUSEDPARM(name);
  if (masscan->echo) {
    return CONF_OK;
  }

  max_offset = strlen(value);

  p_range = range_parse_ipv4(value, &offset, max_offset, &range);
  if (p_range == NULL || (range.begin == 0 && range.end == 0) ||
      range.begin != range.end) {
    LOG(LEVEL_ERROR, "FAIL:  bad redis IP address: %s\n", value);
    return CONF_ERR;
  }
  if (offset < max_offset) {
    while (offset < max_offset && isspace((int)value[offset]))
      offset++;
    if (offset + 1 < max_offset && value[offset] == ':' &&
        isdigit(value[offset + 1] & 0xFF)) {
      port = (unsigned)strtoul(value + offset + 1, 0, 0);
      if (port > 65535 || port == 0) {
        LOG(LEVEL_ERROR, "FAIL: bad redis port: %s\n", value + offset + 1);
        return CONF_ERR;
      }
    }
  }

  /* TODO: add support for connecting to IPv6 addresses here */
  masscan->redis.ip.ipv4 = range.begin;
  masscan->redis.ip.version = 4;
  masscan->redis.port = port;
  masscan->output.format = Output_Redis;
  strcpy_s(masscan->output.filename, sizeof(masscan->output.filename),
           "<redis>");

  return CONF_OK;
}

static void CLEANUP_redis(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_release_memory(struct Masscan *masscan, const char *name,
                              const char *value) {
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_WARNING, "nmap(%s): this is our default option\n", name);
  return CONF_ERR;
}

static void CLEANUP_release_memory(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_resume(struct Masscan *masscan, const char *name,
                      const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  masscan_read_config_file(masscan, value);
  masscan_set_parameter(masscan, "output-append", "true");
  return CONF_OK;
}

static void CLEANUP_resume(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_vuln(struct Masscan *masscan, const char *name,
                    const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (EQUALS("heartbleed", value)) {
    masscan_set_parameter(masscan, "heartbleed", "true");
    return CONF_OK;
  } else if (EQUALS("ticketbleed", value)) {
    masscan_set_parameter(masscan, "ticketbleed", "true");
    return CONF_OK;
  } else if (EQUALS("poodle", value) || EQUALS("sslv3", value)) {
    masscan->is_poodle_sslv3 = 1;
    masscan_set_parameter(masscan, "no-capture", "cert");
    masscan_set_parameter(masscan, "banners", "true");
    return CONF_OK;
  }

  if (!vulncheck_lookup(value)) {
    LOG(LEVEL_ERROR, "FAIL: vuln check '%s' does not exist\n", value);
    LOG(LEVEL_ERROR, "  hint: use '--vuln list' to list available scripts\n");
    return CONF_ERR;
  }

  if (masscan->vuln_name != NULL) {
    if (strcmp(masscan->vuln_name, value) == 0)
      return CONF_OK;
    else {
      LOG(LEVEL_ERROR, "FAIL: only one vuln check supported at a time\n");
      LOG(LEVEL_ERROR,
          "  hint: '%s' is existing vuln check, '%s' is new vuln check\n",
          masscan->vuln_name, value);
      return CONF_ERR;
    }
  }
  masscan->vuln_name = vulncheck_lookup(value)->name;
  return CONF_OK;
}

static void CLEANUP_vuln(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_scan_delay(struct Masscan *masscan, const char *name,
                          const char *value) {
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): unsupported: we do timing VASTLY differently!\n",
      name);
  return CONF_ERR;
}

static void CLEANUP_scan_delay(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_scanflags(struct Masscan *masscan, const char *name,
                         const char *value) {
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): TCP scan flags not yet supported\n", name);
  return CONF_ERR;
}

static void CLEANUP_scanflags(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_sendq(struct Masscan *masscan, const char *name,
                     const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->is_sendq) {
      fprintf(masscan->echo, "sendq = true\n");
    }
    return CONF_OK;
  }

  masscan->is_sendq = parseBoolean(value);
  return CONF_OK;
}

static void CLEANUP_sendq(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_send_eth(struct Masscan *masscan, const char *name,
                        const char *value) {
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): unnecessary, we always do --send-eth\n", name);
  return CONF_WARN;
}

static void CLEANUP_send_eth(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_send_ip(struct Masscan *masscan, const char *name,
                       const char *value) {
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): unsupported, we only do --send-eth\n", name);
  return CONF_ERR;
}

static void CLEANUP_send_ip(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_selftest(struct Masscan *masscan, const char *name,
                        const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (parseBoolean(value)) {
    masscan->op = Operation_Selftest;
  }
  return CONF_OK;
}

static void CLEANUP_selftest(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_benchmark(struct Masscan *masscan, const char *name,
                         const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (parseBoolean(value)) {
    masscan->op = Operation_Benchmark;
  }
  return CONF_OK;
}

static void CLEANUP_benchmark(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_no_stylesheet(struct Masscan *masscan, const char *name,
                             const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (parseBoolean(value)) {
    masscan->output.stylesheet[0] = '\0';
  }
  return CONF_OK;
}

static void CLEANUP_no_stylesheet(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_system_dns(struct Masscan *masscan, const char *name,
                          const char *value) {
  UNUSEDPARM(name);
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR,
      "nmap(%s): DNS lookups will never be supported by this code\n", name);
  return CONF_ERR;
}

static void CLEANUP_system_dns(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_top_ports(struct Masscan *masscan, const char *name,
                         const char *value) {
  unsigned n;
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->top_ports) {
      fprintf(masscan->echo, "top-ports = %u\n", masscan->top_ports);
    }
    return CONF_OK;
  }

  n = (unsigned)parseInt(value);
  if (!isInteger(value)) {
    n = 100;
  }
  LOG(LEVEL_DEBUG, "top-ports = %u\n", n);
  masscan->top_ports = n;
  return CONF_OK;
}

static void CLEANUP_top_ports(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_traceroute(struct Masscan *masscan, const char *name,
                          const char *value) {
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): unsupported\n", name);
  return CONF_ERR;
}

static void CLEANUP_traceroute(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_test(struct Masscan *masscan, const char *name,
                    const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (EQUALS("test", name)) {
    if (EQUALS("csv", value)) {
      masscan->is_test_csv = parseBoolean(value);
    } else {
      LOG(LEVEL_ERROR, "%s %s: unsupported\n", value, name);
    }
  } else if (EQUALS("notest", name)) {
    if (EQUALS("csv", value)) {
      masscan->is_test_csv = !parseBoolean(value);
    } else {
      LOG(LEVEL_ERROR, "%s %s: unsupported\n", value, name);
    }
  } else {
    LOG(LEVEL_ERROR, "%s %s: unsupported\n", value, name);
  }
  return CONF_OK;
}

static void CLEANUP_test(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_ttl(struct Masscan *masscan, const char *name,
                   const char *value) {
  unsigned x;
  UNUSEDPARM(name);

  if (masscan->echo) {
    if (masscan->nmap.ttl) {
      fprintf(masscan->echo, "ttl = %u\n", masscan->nmap.ttl);
    }
    return CONF_OK;
  }

  x = (unsigned)strtoul(value, 0, 0);
  if (x >= 256) {
    LOG(LEVEL_WARNING, "error: %s=<n>: expected number less than 256\n", name);
    return CONF_ERR;
  }

  masscan->nmap.ttl = x;
  return CONF_OK;
}

static void CLEANUP_ttl(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_version(struct Masscan *masscan, const char *name,
                       const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (parseBoolean(value)) {
    masscan->op = Operation_Version;
  }
  return CONF_OK;
}

static void CLEANUP_version(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_version_intensity(struct Masscan *masscan, const char *name,
                                 const char *value) {
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): unsupported\n", name);
  return CONF_ERR;
}

static void CLEANUP_version_intensity(struct Masscan *masscan,
                                      const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_version_light(struct Masscan *masscan, const char *name,
                             const char *value) {
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): unsupported\n", name);
  return CONF_ERR;
}

static void CLEANUP_version_light(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_version_all(struct Masscan *masscan, const char *name,
                           const char *value) {
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): unsupported\n", name);
  return CONF_ERR;
}

static void CLEANUP_version_all(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_version_trace(struct Masscan *masscan, const char *name,
                             const char *value) {
  UNUSEDPARM(value);

  if (masscan->echo) {
    return CONF_OK;
  }

  LOG(LEVEL_ERROR, "nmap(%s): unsupported\n", name);
  return CONF_ERR;
}

static void CLEANUP_version_trace(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_vlan(struct Masscan *masscan, const char *name,
                    const char *value) {
  size_t index;

  if (masscan->echo) {
    return CONF_OK;
  }

  index = ARRAY(name);
  if (index >= ARRAY_SIZE(masscan->nic)) {
    LOG(LEVEL_ERROR, "%s: bad index\n", name);
    return CONF_ERR;
  }

  masscan->nic[index].is_vlan = 1;
  masscan->nic[index].vlan_id = (unsigned)parseInt(value);
  return CONF_OK;
}

static void CLEANUP_vlan(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_wait(struct Masscan *masscan, const char *name,
                    const char *value) {
  UNUSEDPARM(name);
  if (masscan->echo) {
    if (masscan->wait) {
      if (masscan->wait >= INT_MAX) {
        fprintf(masscan->echo, "wait = forever\n");
      } else {
        fprintf(masscan->echo, "wait = %" PRIuPTR "\n", (size_t)masscan->wait);
      }
    }
    return CONF_OK;
  }

  if (EQUALS("forever", value)) {
    masscan->wait = INT_MAX;
  } else {
    masscan->wait = (time_t)parseInt(value);
  }
  return CONF_OK;
}

static void CLEANUP_wait(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

static int SET_webxml(struct Masscan *masscan, const char *name,
                      const char *value) {
  UNUSEDPARM(name);

  if (masscan->echo) {
    return CONF_OK;
  }

  if (parseBoolean(value)) {
    masscan_set_parameter(masscan, "stylesheet",
                          "http://nmap.org/svn/docs/nmap.xsl");
  }
  return CONF_OK;
}

static void CLEANUP_webxml(struct Masscan *masscan, const char *name) {
  UNUSEDPARM(name);
  UNUSEDPARM(masscan);
  return;
}

enum { F_NONE = 0, F_BOOL = 1, F_CMPSTART = 2 };

struct ConfigParameter {
  const char *name;
  SET_PARAMETER set;
  CLENUP_PARAMETER cleanup;
  unsigned flags;
  const char *alts[8];
};

struct ConfigParameter config_parameters[] = {
    {"resume-index", SET_resume_index, CLEANUP_resume_index, 0, {NULL}},
    {"resume-count", SET_resume_count, CLEANUP_resume_count, 0, {NULL}},
    {"seed", SET_seed, CLEANUP_seed, 0, {NULL}},
    {"arpscan", SET_arpscan, CLEANUP_arpscan, F_BOOL, {"arp", NULL}},
    {"randomize-hosts",
     SET_randomize_hosts,
     CLEANUP_randomize_hosts,
     F_BOOL,
     {NULL}},
    {"rate", SET_rate, CLEANUP_rate, 0, {"max-rate", "min-rate", NULL}},
    {"tranquility", SET_tranquility, CLEANUP_tranquility, F_BOOL, {NULL}},
    {"shard", SET_shard, CLEANUP_shard, 0, {"shards", NULL}},
    {"num-handle-threads",
     SET_num_handle_threads,
     CLEANUP_num_handle_threads,
     0,
     {NULL}},
    {"banners",
     SET_banners,
     CLEANUP_banners,
     F_BOOL,
     {"banner", "nobanners", "nobanner", NULL}},
    {"dynamic-ssl",
     SET_dynamic_ssl,
     CLEANUP_dynamic_ssl,
     F_BOOL,
     {"dynamic-ssl", NULL}},
    {"dynamic-set-host",
     SET_dynamic_set_host,
     CLEANUP_dynamic_set_host,
     F_BOOL,
     {NULL}},
    {"regex-only-banners",
     SET_regex_only_banners,
     CLEANUP_regex_only_banners,
     F_BOOL,
     {NULL}},
    {"regex", SET_regex, CLEANUP_regex, 0, {"regex", NULL}},
    {"retries",
     SET_retries,
     CLEANUP_retries,
     0,
     {"retry", "max-retries", "max-retry", NULL}},
    {"noreset", SET_noreset, CLEANUP_noreset, F_BOOL, {NULL}},
    {"nmap-payloads",
     SET_nmap_payloads,
     CLEANUP_nmap_payloads,
     0,
     {"nmap-payload", NULL}},
    {"nmap-service-probes",
     SET_nmap_service_probes,
     CLEANUP_nmap_service_probes,
     0,
     {"nmap-service-probe", NULL}},
    {"pcap-filename",
     SET_pcap_filename,
     CLEANUP_pcap_filename,
     0,
     {"pcap", NULL}},
    {"pcap-payloads",
     SET_pcap_payloads,
     CLEANUP_pcap_payloads,
     0,
     {"pcap-payload", NULL}},
    {"hello", SET_hello, CLEANUP_hello, 0, {NULL}},
    {"hello-file",
     SET_hello_file,
     CLEANUP_hello_file,
     0,
     {"hello-filename", NULL}},
    {"hello-string", SET_hello_string, CLEANUP_hello_string, 0, {NULL}},
    {"hello-timeout", SET_hello_timeout, CLEANUP_hello_timeout, 0, {NULL}},
    {"http-cookie", SET_http_cookie, CLEANUP_http_cookie, 0, {NULL}},
    {"http-header",
     SET_http_header,
     CLEANUP_http_header,
     F_CMPSTART,
     {"http-field", NULL}},
    {"http-method", SET_http_method, CLEANUP_http_method, 0, {NULL}},
    {"http-version", SET_http_version, CLEANUP_http_version, 0, {NULL}},
    {"http-url", SET_http_url, CLEANUP_http_url, 0, {"http-uri", NULL}},
    {"http-user-agent",
     SET_http_user_agent,
     CLEANUP_http_user_agent,
     0,
     {"http-useragent", NULL}},
    {"http-host", SET_http_host, CLEANUP_http_host, 0, {NULL}},
    {"http-payload", SET_http_payload, CLEANUP_http_payload, 0, {NULL}},
    {"ndjson-status",
     SET_status_ndjson,
     CLEANUP_status_ndjson,
     F_BOOL,
     {"status-ndjson", NULL}},
    {"json-status",
     SET_status_json,
     CLEANUP_status_json,
     F_BOOL,
     {"status-json", NULL}},
    {"min-packet", SET_min_packet, CLEANUP_min_packet, 0, {"min-pkt", NULL}},
    {"capture", SET_capture, CLEANUP_capture, 0, {"nocapture", NULL}},
    {"SPACE", SET_space, CLEANUP_space, 0, {NULL}},
    {"output-filename",
     SET_output_filename,
     CLEANUP_output_filename,
     0,
     {"output-file", NULL}},
    {"output-filename-ssl-keys",
     SET_output_filename_ssl_keys,
     CLEANUP_output_filename_ssl_keys,
     0,
     {"output-file-ssl-keys", NULL}},
    {"output-format", SET_output_format, CLEANUP_output_format, 0, {NULL}},
    {"output-show",
     SET_output_show,
     CLEANUP_output_show,
     0,
     {"output-status", "show", NULL}},
    {"output-noshow",
     SET_output_noshow,
     CLEANUP_output_noshow,
     0,
     {"noshow", NULL}},
    {"output-show-open",
     SET_output_show_open,
     CLEANUP_output_show_open,
     F_BOOL,
     {"open", "open-only", NULL}},
    {"output-append",
     SET_output_append,
     CLEANUP_output_append,
     F_BOOL,
     {"append-output", NULL}},
    {"rotate",
     SET_rotate_time,
     CLEANUP_rotate_time,
     0,
     {"output-rotate", "rotate-output", "rotate-time", NULL}},
    {"rotate-dir",
     SET_rotate_directory,
     CLEANUP_rotate_directory,
     0,
     {"output-rotate-dir", "rotate-directory", NULL}},
    {"rotate-offset",
     SET_rotate_offset,
     CLEANUP_rotate_offset,
     0,
     {"output-rotate-offset", NULL}},
    {"rotate-size",
     SET_rotate_filesize,
     CLEANUP_rotate_filesize,
     0,
     {"output-rotate-filesize", "rotate-filesize", NULL}},
    {"stylesheet", SET_output_stylesheet, CLEANUP_output_stylesheet, 0, {NULL}},
    {"script", SET_script, CLEANUP_script, 0, {NULL}},
    {"config", SET_config, CLEANUP_config, 0, {"conf", NULL}},
    {"adapter", SET_adapter, CLEANUP_adapter, 0, {"if", "interface", NULL}},
    {"adapter-ip",
     SET_adapter_ip,
     CLEANUP_adapter_ip,
     0,
     {"source-ip", "source-address", "spoof-ip", "spoof-address", "src-ip",
      NULL}},
    {"adapter-port",
     SET_adapter_port,
     CLEANUP_adapter_port,
     0,
     {"source-port", "spoof-port", "src-port", "sourceport", NULL}},
    {"adapter-mac",
     SET_adapter_mac,
     CLEANUP_adapter_mac,
     0,
     {"source-mac", "spoof-mac", "src-mac", NULL}},
    {"router-mac",
     SET_router_mac,
     CLEANUP_router_mac,
     0,
     {"router", "dest-mac", "dst-mac", "destination-mac", "target-mac", NULL}},
    {"router-mac-ipv4",
     SET_router_mac_ipv4,
     CLEANUP_router_mac_ipv4,
     0,
     {"router-ipv4", NULL}},
    {"router-mac-ipv6",
     SET_router_mac_ipv6,
     CLEANUP_router_mac_ipv6,
     0,
     {"router-ipv6", NULL}},
    {"router-ip", SET_router_ip, CLEANUP_router_ip, 0, {NULL}},
    {"udp-ports", SET_udp_ports, CLEANUP_udp_ports, 0, {"udp-port", NULL}},
    {"oprotos", SET_oprotos, CLEANUP_oprotos, 0, {"oproto", NULL}},
    {"tcp-ports", SET_tcp_ports, CLEANUP_tcp_ports, 0, {"tcp-port", NULL}},
    {"ports",
     SET_ports,
     CLEANUP_ports,
     0,
     {"port", "dest-port", "dst-port", "destination-port", "target-port",
      NULL}},
    {"banner-types",
     SET_banner_types,
     CLEANUP_banner_types,
     0,
     {"banner-type", "banner-apps", "banner-app", NULL}},
    {"exclude-ports",
     SET_exclude_ports,
     CLEANUP_exclude_ports,
     0,
     {"exclude-port", NULL}},
    {"bpf", SET_bpf, CLEANUP_bpf, 0, {NULL}},
    {"ping", SET_ping, CLEANUP_ping, F_BOOL, {"ping-sweep", NULL}},
    {"range",
     SET_range,
     CLEANUP_range,
     0,
     {"ranges", "ip", "ipv4", "dest-ip", "dst-ip", "destination-ip",
      "target-ip", NULL}},
    {"exclude",
     SET_exclude,
     CLEANUP_exclude,
     0,
     {"exclude-range", "exclude-ranges", "exclude-ip", "exclude-ipv4", NULL}},
    {"badsum", SET_badsum, CLEANUP_badsum, F_BOOL, {NULL}},
    {"backtrace", NULL, NULL, F_BOOL, {"nobacktrace", NULL}},
    {"banner1", SET_test_banner1, CLEANUP_test_banner1, 0, {NULL}},
    {"blackrock-rounds",
     SET_blackrock_rounds,
     CLEANUP_blackrock_rounds,
     0,
     {NULL}},
    {"connection-timeout",
     SET_connection_timeout,
     CLEANUP_connection_timeout,
     0,
     {"tcp-timeout", NULL}},
    {"datadir", SET_datadir, CLEANUP_datadir, 0, {NULL}},
    {"data-length", SET_data_length, CLEANUP_data_length, 0, {NULL}},
    {"debug", SET_debug, CLEANUP_debug, 0, {NULL}},
    {"dns-servers", SET_dns_servers, CLEANUP_dns_servers, 0, {NULL}},
    {"echo", SET_echo, CLEANUP_echo, F_BOOL, {"echo-all", NULL}},
    {"excludefile", SET_excludefile, CLEANUP_excludefile, 0, {NULL}},
    {"heartbleed", SET_heartbleed, CLEANUP_heartbleed, F_BOOL, {NULL}},
    {"ticketbleed", SET_ticketbleed, CLEANUP_ticketbleed, F_BOOL, {NULL}},
    {"host-timeout", SET_host_timeout, CLEANUP_host_timeout, 0, {NULL}},
    {"iflist", SET_iflist, CLEANUP_iflist, F_BOOL, {NULL}},
    {"includefile", SET_includefile, CLEANUP_includefile, 0, {NULL}},
    {"infinite", SET_infinite, CLEANUP_infinite, F_BOOL, {NULL}},
    {"interactive",
     SET_interactive,
     CLEANUP_interactive,
     F_BOOL,
     {"nointeractive", NULL}},
    {"status", SET_status, CLEANUP_status, F_BOOL, {"nostatus", NULL}},
    {"ip-options", SET_ip_options, CLEANUP_ip_options, 0, {NULL}},
    {"log-errors", SET_log_errors, CLEANUP_log_errors, F_BOOL, {NULL}},
    {"min-hostgroup",
     SET_hostgroup,
     CLEANUP_hostgroup,
     0,
     {"max-hostgroup", NULL}},
    {"min-parallelism",
     SET_parallelism,
     CLEANUP_parallelism,
     0,
     {"max-parallelism", NULL}},
    {"min-rtt-timeout",
     SET_rtt_timeout,
     CLEANUP_rtt_timeout,
     0,
     {"max-rtt-timeout", "initial-rtt-timeout", NULL}},
    {"mtu", SET_mtu, CLEANUP_mtu, 0, {NULL}},
    {"nmap", SET_nmap, CLEANUP_nmap, F_BOOL, {NULL}},
    {"offline",
     SET_offline,
     CLEANUP_offline,
     F_BOOL,
     {"notransmit", "nosend", "dry-run", NULL}},
    {"osscan-limit", SET_osscan_limit, CLEANUP_osscan_limit, F_BOOL, {NULL}},
    {"osscan-guess", SET_osscan_guess, CLEANUP_osscan_guess, F_BOOL, {NULL}},
    {"packet-trace",
     SET_packet_trace,
     CLEANUP_packet_trace,
     F_BOOL,
     {"trace-packet", NULL}},
    {"privileged",
     SET_privileged,
     CLEANUP_privileged,
     F_BOOL,
     {"unprivileged", NULL}},
    {"pfring", SET_pfring, CLEANUP_pfring, F_BOOL, {NULL}},
    {"port-ratio", SET_port_ratio, CLEANUP_port_ratio, 0, {NULL}},
    {"readrange",
     SET_readrange,
     CLEANUP_readrange,
     F_BOOL,
     {"read-range", "read-ranges", "readranges", NULL}},
    {"reason", SET_reason, CLEANUP_reason, F_BOOL, {NULL}},
    {"redis", SET_redis, CLEANUP_redis, 0, {NULL}},
    {"release-memory",
     SET_release_memory,
     CLEANUP_release_memory,
     F_BOOL,
     {NULL}},
    {"resume", SET_resume, CLEANUP_resume, 0, {NULL}},
    {"vuln", SET_vuln, CLEANUP_vuln, 0, {NULL}},
    {"scan-delay",
     SET_scan_delay,
     CLEANUP_scan_delay,
     0,
     {"max-scan-delay", NULL}},
    {"scanflags", SET_scanflags, CLEANUP_scanflags, 0, {NULL}},
    {"sendq", SET_sendq, CLEANUP_sendq, F_BOOL, {"sendqueue", NULL}},
    {"send-eth", SET_send_eth, CLEANUP_send_eth, F_BOOL, {NULL}},
    {"send-ip", SET_send_ip, CLEANUP_send_ip, F_BOOL, {NULL}},
    {"selftest",
     SET_selftest,
     CLEANUP_selftest,
     F_BOOL,
     {"self-test", "regress", NULL}},
    {"benchmark", SET_benchmark, CLEANUP_benchmark, F_BOOL, {NULL}},
    {"no-stylesheet", SET_no_stylesheet, CLEANUP_no_stylesheet, F_BOOL, {NULL}},
    {"system-dns", SET_system_dns, CLEANUP_system_dns, F_BOOL, {NULL}},
    {"top-ports", SET_top_ports, CLEANUP_top_ports, 0, {NULL}},
    {"traceroute", SET_traceroute, CLEANUP_traceroute, F_BOOL, {NULL}},
    {"test", SET_test, CLEANUP_test, 0, {"notest", NULL}},
    {"ttl", SET_ttl, CLEANUP_ttl, 0, {NULL}},
    {"version", SET_version, CLEANUP_version, F_BOOL, {NULL}},
    {"version-intensity",
     SET_version_intensity,
     CLEANUP_version_intensity,
     F_BOOL,
     {NULL}},
    {"version-light", SET_version_light, CLEANUP_version_light, F_BOOL, {NULL}},
    {"version-all", SET_version_all, CLEANUP_version_all, F_BOOL, {NULL}},
    {"version-trace", SET_version_trace, CLEANUP_version_trace, F_BOOL, {NULL}},
    {"vlan", SET_vlan, CLEANUP_vlan, 0, {"adapter-vlan", NULL}},
    {"wait", SET_wait, CLEANUP_wait, 0, {NULL}},
    {"webxml", SET_webxml, CLEANUP_webxml, F_BOOL, {NULL}},
    {"SPACE", SET_space, CLEANUP_space, 0, {NULL}},
    {NULL}};

static int EQUALS_PARAMS_FLAGS(const char *lhs, const char *rhs,
                               size_t rhs_length, unsigned flags) {
  if (flags & F_CMPSTART) {
    return EQUALSx(lhs, rhs, rhs_length);
  }
  return EQUALS(lhs, rhs);
}

static struct ConfigParameter *find_config_parameters(const char *name) {
  size_t i, j;
  size_t len_name = strlen(name);

  for (i = 0; config_parameters[i].name; i++) {
    if (EQUALS_PARAMS_FLAGS(config_parameters[i].name, name, len_name,
                            config_parameters[i].flags)) {
      return &config_parameters[i];
    }

    for (j = 0; config_parameters[i].alts[j]; j++) {
      if (EQUALS_PARAMS_FLAGS(config_parameters[i].alts[j], name, len_name,
                              config_parameters[i].flags)) {
        return &config_parameters[i];
      }
    }
  }

  return NULL;
}

/***************************************************************************
 * Called either from the "command-line" parser when it sees a --param,
 * or from the "config-file" parser for normal options.
 ***************************************************************************/
void masscan_set_parameter(struct Masscan *masscan, const char *name,
                           const char *value) {

  unsigned status = CONF_ERR;
  struct ConfigParameter *config_parameter;

  /* Go through configured list of parameters */
  config_parameter = find_config_parameters(name);
  if (config_parameter == NULL) {
    LOG(LEVEL_ERROR, "CONF: unknown config option: %s=%s\n", name, value);
    exit(1);
  }

  if (config_parameter->set == NULL) {
    return;
  }
  status = config_parameter->set(masscan, name, value);
  if (status == CONF_OK) {
    LOG(LEVEL_DEBUG, "CONF: set config option success: %s=%s\n", name, value);
  } else if (status == CONF_WARN) {
    LOG(LEVEL_WARNING, "CONF: set config option warning: %s=%s\n", name, value);
  } else {
    LOG(LEVEL_ERROR, "CONF: set config option error: %s=%s\n", name, value);
    exit(1);
  }
}

void masscan_clenup_params(struct Masscan *masscan) {
  size_t i;
  for (i = 0; config_parameters[i].name; i++) {
    if (config_parameters[i].cleanup) {
      config_parameters[i].cleanup(masscan, config_parameters[i].name);
    }
  }
}

/***************************************************************************
 * Command-line parsing code assumes every --param is followed by a value.
 * This is a list of the parameters that don't follow the default.
 ***************************************************************************/
static int is_singleton(const char *name) {
  struct ConfigParameter *config_parameter = find_config_parameters(name);
  if (config_parameter == NULL) {
    LOG(LEVEL_ERROR, "CONF: unknown config option: %s\n", name);
    exit(1);
  }
  return config_parameter->flags & F_BOOL;
}

/*****************************************************************************
 *****************************************************************************/
static void masscan_help() {
  printf(
      "MASSCAN is a fast port scanner. The primary input parameters are the\n"
      "IP addresses/ranges you want to scan, and the port numbers. An example\n"
      "is the following, which scans the 10.x.x.x network for web servers:\n"
      " masscan 10.0.0.0/8 -p80\n"
      "The program auto-detects network interface/adapter settings. If this\n"
      "fails, you'll have to set these manually. The following is an\n"
      "example of all the parameters that are needed:\n"
      " --adapter-ip 192.168.10.123\n"
      " --adapter-mac 00-11-22-33-44-55\n"
      " --router-mac 66-55-44-33-22-11\n"
      "Parameters can be set either via the command-line or config-file. The\n"
      "names are the same for both. Thus, the above adapter settings would\n"
      "appear as follows in a configuration file:\n"
      " adapter-ip = 192.168.10.123\n"
      " adapter-mac = 00-11-22-33-44-55\n"
      " router-mac = 66-55-44-33-22-11\n"
      "All single-dash parameters have a spelled out double-dash equivalent,\n"
      "so '-p80' is the same as '--ports 80' (or 'ports = 80' in config "
      "file).\n"
      "To use the config file, type:\n"
      " masscan -c <filename>\n"
      "To generate a config-file from the current settings, use the --echo\n"
      "option. This stops the program from actually running, and just echoes\n"
      "the current configuration instead. This is a useful way to generate\n"
      "your first config file, or see a list of parameters you didn't know\n"
      "about. I suggest you try it now:\n"
      " masscan -p1234 --echo\n");
  exit(1);
}

/***************************************************************************
 ***************************************************************************/
void masscan_load_database_files(struct Masscan *masscan) {
  const char *filename;

  /*
   * "pcap-payloads"
   */
  filename = masscan->payloads.pcap_payloads_filename;
  if (filename) {
    if (masscan->payloads.udp == NULL)
      masscan->payloads.udp = payloads_udp_create();
    if (masscan->payloads.oproto == NULL)
      masscan->payloads.oproto = payloads_udp_create();

    payloads_read_pcap(filename, masscan->payloads.udp,
                       masscan->payloads.oproto);
  }

  /* "nmap-payloads" */
  filename = masscan->payloads.nmap_payloads_filename;
  if (filename) {
    FILE *fp;
    int err;

    err = fopen_s(&fp, filename, "rt");
    if (err || fp == NULL) {
      LOG(LEVEL_WARNING, "%s: %s\n", filename, strerror(errno));
    } else {
      if (masscan->payloads.udp == NULL) {
        masscan->payloads.udp = payloads_udp_create();
      }

      payloads_udp_readfile(fp, filename, masscan->payloads.udp);

      fclose(fp);
    }
  }

  /* "nmap-service-probes" */
  filename = masscan->payloads.nmap_service_probes_filename;
  if (filename) {
    if (masscan->payloads.probes)
      nmapserviceprobes_free(masscan->payloads.probes);

    masscan->payloads.probes = nmapserviceprobes_read_file(filename);
  }
}

/***************************************************************************
 * Read the configuration from the command-line.
 * Called by 'main()' when starting up.
 ***************************************************************************/
void masscan_command_line(struct Masscan *masscan, int argc, char *argv[]) {
  ptrdiff_t i;

  for (i = 1; i < argc; i++) {
    /*
     * --name=value
     * --name:value
     * -- name value
     */
    if (argv[i][0] == '-' && argv[i][1] == '-') {
      if (strcmp(argv[i], "--help") == 0) {
        masscan_help();
      } else if (EQUALS("top-ports", argv[i] + 2)) {
        /* special handling here since the following parameter
         * is optional */
        const char *value = "1000";
        unsigned n;

        /* Only consume the next parameter if it's a number,
         * otherwise default to 10000 */
        if (i + 1 < argc && isInteger(argv[i + 1])) {
          value = argv[++i];
        }
        n = (unsigned)parseInt(value);
        LOG(LEVEL_DEBUG, "top-ports = %u\n", n);
        masscan->top_ports = n;

      } else if (EQUALS("readscan", argv[i] + 2)) {
        /* Read in a binary file instead of scanning the network*/
        masscan->op = Operation_ReadScan;

        /* Default to reading banners */
        masscan->is_banners = 1;

        /* This option may be followed by many filenames, therefore,
         * skip forward in the argument list until the next
         * argument */
        while (i + 1 < argc && argv[i + 1][0] != '-')
          i++;
        continue;
      } else {
        char name2[64];
        char *name = argv[i] + 2;
        size_t name_length;
        const char *value;

        value = strchr(&argv[i][2], '=');
        if (value == NULL)
          value = strchr(&argv[i][2], ':');
        if (value == NULL) {
          if (is_singleton(name))
            value = "";
          else
            value = argv[++i];
          name_length = strlen(name);
        } else {
          name_length = value - name;
          value++;
        }

        if (i >= argc) {
          LOG(LEVEL_WARNING, "%.*s: empty parameter\n", (int)name_length, name);
          break;
        }

        if (name_length > sizeof(name2) - 1) {
          LOG(LEVEL_WARNING, "%.*s: name too long\n", (int)name_length, name);
          name_length = sizeof(name2) - 1;
        }

        memcpy(name2, name, name_length);
        name2[name_length] = '\0';

        masscan_set_parameter(masscan, name2, value);
      }
      continue;
    }

    /* For for a single-dash parameter */
    if (argv[i][0] == '-') {
      const char *arg;

      switch (argv[i][1]) {
      case '6':
        /* Silently ignore this: IPv6 features enabled all the time */
        break;
      case 'A':
        LOG(LEVEL_ERROR,
            "nmap(%s): unsupported: this tool only does SYN scan\n", argv[i]);
        exit(1);
      case 'b':
        LOG(LEVEL_ERROR, "nmap(%s): FTP bounce scans will never be supported\n",
            argv[i]);
        exit(1);
      case 'c':
        if (argv[i][2])
          arg = argv[i] + 2;
        else
          arg = argv[++i];
        masscan_read_config_file(masscan, arg);
        break;
      case 'd': /* just do same as verbosity level */
      {
        size_t v;
        for (v = 1; argv[i][v] == 'd'; v++) {
          LOG_add_level(1);
        }
      } break;
      case 'e':
        if (argv[i][2])
          arg = argv[i] + 2;
        else
          arg = argv[++i];
        masscan_set_parameter(masscan, "adapter", arg);
        break;
      case 'f':
        LOG(LEVEL_ERROR, "nmap(%s): fragmentation not yet supported\n",
            argv[i]);
        exit(1);
      case 'F':
        LOG(LEVEL_ERROR, "nmap(%s): unsupported, no slow/fast mode\n", argv[i]);
        exit(1);
      case 'g':
        if (argv[i][2])
          arg = argv[i] + 2;
        else
          arg = argv[++i];
        masscan_set_parameter(masscan, "adapter-port", arg);
        break;
      case 'h':
      case '?':
        masscan_usage();
        break;
      case 'i':
        if (argv[i][3] == '\0' && !isdigit(argv[i][2] & 0xFF)) {
          /* This looks like an nmap option*/
          switch (argv[i][2]) {
          case 'L':
            masscan_set_parameter(masscan, "includefile", argv[++i]);
            break;
          case 'R':
            /* -iR in nmap makes it randomize addresses completely. Thus,
             * it's nearest equivalent is scanning the entire Internet range */
            masscan_set_parameter(masscan, "include", "0.0.0.0/0");
            break;
          default:
            LOG(LEVEL_ERROR, "nmap(%s): unsupported option\n", argv[i]);
            exit(1);
          }

        } else {
          if (argv[i][2])
            arg = argv[i] + 2;
          else
            arg = argv[++i];

          masscan_set_parameter(masscan, "adapter", arg);
        }
        break;
      case 'n':
        /* This looks like an nmap option*/
        /* Do nothing: this code never does DNS lookups anyway */
        break;
      case 'o': /* nmap output format */
        switch (argv[i][2]) {
        case 'A':
          masscan->output.format = Output_All;
          LOG(LEVEL_ERROR, "nmap(%s): unsupported output format\n", argv[i]);
          exit(1);
        case 'B':
          masscan->output.format = Output_Binary;
          break;
        case 'D':
          masscan->output.format = Output_NDJSON;
          break;
        case 'J':
          masscan->output.format = Output_JSON;
          break;
        case 'N':
          masscan->output.format = Output_Nmap;
          LOG(LEVEL_ERROR, "nmap(%s): unsupported output format\n", argv[i]);
          exit(1);
        case 'X':
          masscan->output.format = Output_XML;
          break;
        case 'R':
          masscan->output.format = Output_Redis;
          if (i + 1 < argc && argv[i + 1][0] != '-')
            masscan_set_parameter(masscan, "redis", argv[i + 1]);
          break;
        case 'S':
          masscan->output.format = Output_ScriptKiddie;
          LOG(LEVEL_ERROR, "nmap(%s): unsupported output format\n", argv[i]);
          exit(1);
        case 'G':
          masscan->output.format = Output_Grepable;
          break;
        case 'L':
          masscan_set_parameter(masscan, "output-format", "list");
          break;
        case 'U':
          masscan_set_parameter(masscan, "output-format", "unicornscan");
          break;
        case 'H':
          masscan_set_parameter(masscan, "output-format", "hostonly");
          break;
        default:
          LOG(LEVEL_ERROR, "nmap(%s): unknown output format\n", argv[i]);
          exit(1);
        }

        ++i;
        if (i >= argc || (argv[i][0] == '-' && argv[i][1] != '\0')) {
          LOG(LEVEL_ERROR, "missing output filename\n");
          exit(1);
        }

        masscan_set_parameter(masscan, "output-filename", argv[i]);
        break;
      case 'O':
        LOG(LEVEL_ERROR, "nmap(%s): unsupported, OS detection is too complex\n",
            argv[i]);
        exit(1);
      case 'p':
        if (argv[i][2])
          arg = argv[i] + 2;
        else
          arg = argv[++i];
        if (i >= argc || arg[0] == 0) { // if string is empty
          LOG(LEVEL_WARNING, "%s: empty parameter\n", argv[i]);
        } else
          masscan_set_parameter(masscan, "ports", arg);
        break;
      case 'P':
        switch (argv[i][2]) {
        case 'n':
          /* we already do this */
          break;
        default:
          LOG(LEVEL_ERROR, "nmap(%s): unsupported option, maybe in future\n",
              argv[i]);
          exit(1);
        }
        break;
      case 'r':
        /* This looks like an nmap option*/
        LOG(LEVEL_ERROR,
            "nmap(%s): wat? randomization is our raison d'etre!! rethink "
            "prease\n",
            argv[i]);
        exit(1);
      case 'R':
        /* This looks like an nmap option*/
        LOG(LEVEL_ERROR,
            "nmap(%s): unsupported. This code will never do DNS lookups.\n",
            argv[i]);
        exit(1);
      case 's': /* NMAP: scan type */
        if (argv[i][3] == '\0' && !isdigit(argv[i][2] & 0xFF)) {
          size_t j;
          for (j = 2; argv[i][j]; j++) {
            switch (argv[i][j]) {
            case 'A':
              LOG(LEVEL_ERROR, "nmap(%s): ACK scan not yet supported\n",
                  argv[i]);
              exit(1);
            case 'C':
              LOG(LEVEL_ERROR, "nmap(%s): unsupported\n", argv[i]);
              exit(1);
            case 'F':
              LOG(LEVEL_ERROR, "nmap(%s): FIN scan not yet supported\n",
                  argv[i]);
              exit(1);
            case 'I':
              LOG(LEVEL_ERROR,
                  "nmap(%s): Zombie scans will never be supported\n", argv[i]);
              exit(1);
            case 'L': /* List Scan - simply list targets to scan */
              masscan->op = Operation_ListScan;
              break;
            case 'M':
              LOG(LEVEL_ERROR, "nmap(%s): Maimon scan not yet supported\n",
                  argv[i]);
              exit(1);
            case 'n': /* Ping Scan - disable port scan */
              LOG(LEVEL_ERROR, "nmap(%s): ping-sweeps not yet supported\n",
                  argv[i]);
              exit(1);
            case 'N':
              LOG(LEVEL_ERROR, "nmap(%s): NULL scan not yet supported\n",
                  argv[i]);
              exit(1);
            case 'O': /* Other IP protocols (not ICMP, UDP, TCP, or SCTP) */
              masscan->scan_type.oproto = 1;
              break;
            case 'S': /* TCP SYN scan - THIS IS WHAT WE DO! */
              masscan->scan_type.tcp = 1;
              break;
            case 'T': /* TCP connect scan */
              LOG(LEVEL_ERROR,
                  "nmap(%s): connect() is too synchronous for cool kids\n",
                  argv[i]);
              LOG(LEVEL_ERROR,
                  "WARNING: doing SYN scan (-sS) anyway, ignoring (-sT)\n");
              break;
            case 'U': /* UDP scan */
              masscan->scan_type.udp = 1;
              break;
            case 'V':
              LOG(LEVEL_ERROR, "nmap(%s): unlikely this will be supported\n",
                  argv[i]);
              exit(1);
            case 'W':
              LOG(LEVEL_ERROR, "nmap(%s): Windows scan not yet supported\n",
                  argv[i]);
              exit(1);
            case 'X':
              LOG(LEVEL_ERROR, "nmap(%s): Xmas scan not yet supported\n",
                  argv[i]);
              exit(1);
            case 'Y':
              break;
            case 'Z':
              masscan->scan_type.sctp = 1;
              break;
            default:
              LOG(LEVEL_ERROR, "nmap(%s): unsupported option\n", argv[i]);
              exit(1);
            }
          }

        } else {
          LOG(LEVEL_ERROR, "%s: unknown parameter\n", argv[i]);
          exit(1);
        }
        break;
      case 'S':
        if (argv[i][2])
          arg = argv[i] + 2;
        else
          arg = argv[++i];
        masscan_set_parameter(masscan, "adapter-ip", arg);
        break;
      case 'v': {
        size_t v;
        for (v = 1; argv[i][v] == 'v'; v++) {
          LOG_add_level(1);
        }
      } break;
      case 'V': /* print version and exit */
        masscan_set_parameter(masscan, "version", "");
        break;
      case 'W':
        masscan->op = Operation_List_Adapters;
        return;
      case 'T':
        LOG(LEVEL_ERROR,
            "nmap(%s): unsupported, we do timing WAY different than nmap\n",
            argv[i]);
        exit(1);
      default:
        LOG(LEVEL_ERROR, "FAIL: unknown option: -%s\n", argv[i]);
        LOG(LEVEL_ERROR, " [hint] try \"--help\"\n");
        LOG(LEVEL_ERROR,
            " [hint] ...or, to list nmap-compatible options, try \"--nmap\"\n");
        exit(1);
      }
      continue;
    }

    if (!isdigit((int)argv[i][0]) && argv[i][0] != ':' && argv[i][0] != '[') {
      LOG(LEVEL_ERROR, "FAIL: unknown command-line parameter \"%s\"\n",
          argv[i]);
      LOG(LEVEL_ERROR, " [hint] did you want \"--%s\"?\n", argv[i]);
      exit(1);
    }

    /* If parameter doesn't start with '-', assume it's an
     * IPv4 range
     */
    masscan_set_parameter(masscan, "range", argv[i]);
  }

  /*
   * If no other "scan type" found, then default to TCP
   */
  if (masscan->scan_type.udp == 0 && masscan->scan_type.sctp == 0 &&
      masscan->scan_type.ping == 0 && masscan->scan_type.arp == 0 &&
      masscan->scan_type.oproto == 0)
    masscan->scan_type.tcp = 1;

  /*
   * If "top-ports" specified, then add all those ports. This may be in
   * addition to any other ports
   */
  if (masscan->top_ports) {
    config_top_ports(masscan, masscan->top_ports);
  }
  if (masscan->shard.of < masscan->shard.one) {
    LOG(LEVEL_WARNING,
        "[-] WARNING: the shard number must be less than the total shard "
        "count: %u/%u\n",
        masscan->shard.one, masscan->shard.of);
  }
  if (masscan->shard.of > 1 && masscan->seed == 0) {
    LOG(LEVEL_WARNING, "[-] WARNING: --seed <num> is not specified\n    HINT: "
                       "all shards must share the same seed\n");
  }
}

/***************************************************************************
 * Prints the current configuration to the command-line then exits.
 * Use#1: create a template file of all settable parameters.
 * Use#2: make sure your configuration was interpreted correctly.
 ***************************************************************************/
void masscan_echo(struct Masscan *masscan, FILE *fp, bool is_echo_all) {
  size_t i;
  unsigned l = 0;

  /* NEW:
   * Print all configuration parameters */
  masscan->echo = fp;
  masscan->echo_all = is_echo_all;
  for (i = 0; config_parameters[i].name; i++) {
    if (config_parameters[i].set) {
      config_parameters[i].set(masscan, NULL, NULL);
    }
  }
  masscan->echo = NULL;
  masscan->echo_all = false;

  /* Targets */
  fprintf(fp, "# TARGET SELECTION (IP, PORTS, EXCLUDES)\n");
  fprintf(fp, "ports = ");
  /* Disable comma generation for the first element */
  l = 0;
  for (i = 0; i < masscan->targets.ports.count; i++) {
    struct Range range = masscan->targets.ports.list[i];
    do {
      struct Range rrange = range;
      unsigned done = 0;
      if (l)
        fprintf(fp, ",");
      l = 1;
      if (rrange.begin >= Templ_Oproto_last) {
        rrange.begin -= Templ_Oproto;
        rrange.end -= Templ_Oproto;
        fprintf(fp, "O:");
        done = 1;
      } else if (rrange.begin >= Templ_ICMP) {
        rrange.begin -= Templ_ICMP;
        rrange.end -= Templ_ICMP;
        fprintf(fp, "I:");
        range.begin = Templ_Oproto;
      } else if (rrange.begin >= Templ_SCTP) {
        rrange.begin -= Templ_SCTP;
        rrange.end -= Templ_SCTP;
        fprintf(fp, "S:");
        range.begin = Templ_ICMP;
      } else if (rrange.begin >= Templ_UDP) {
        rrange.begin -= Templ_UDP;
        rrange.end -= Templ_UDP;
        fprintf(fp, "U:");
        range.begin = Templ_SCTP;
      } else
        range.begin = Templ_UDP;

      rrange.end = min(rrange.end, 65535);
      if (rrange.begin == rrange.end)
        fprintf(fp, "%u", rrange.begin);
      else
        fprintf(fp, "%u-%u", rrange.begin, rrange.end);
      if (done)
        break;
    } while (range.begin <= range.end);
  }
  fprintf(fp, "\n");
  for (i = 0; i < masscan->targets.ipv4.count; i++) {
    struct Range range = masscan->targets.ipv4.list[i];
    ipaddress_formatted_t fmt;
    ipv4address_fmt(&fmt, &range.begin);

    fprintf(fp, "range = %s", fmt.string);
    if (range.begin != range.end) {
      unsigned cidr_bits = count_cidr_bits(range);
      if (cidr_bits) {
        fprintf(fp, "/%u", cidr_bits);
      } else {
        ipv4address_fmt(&fmt, &range.end);
        fprintf(fp, "-%s", fmt.string);
      }
    }
    fprintf(fp, "\n");
  }
  for (i = 0; i < masscan->targets.ipv6.count; i++) {
    struct Range6 range = masscan->targets.ipv6.list[i];
    ipaddress_formatted_t fmt;
    ipv6address_fmt(&fmt, &range.begin);

    fprintf(fp, "range = %s", fmt.string);
    if (!ipv6address_is_equal(&range.begin, &range.end)) {
      unsigned cidr_bits = count_cidr6_bits(&range);

      if (cidr_bits) {
        fprintf(fp, "/%u", cidr_bits);
      } else {
        ipv6address_fmt(&fmt, &range.end);
        fprintf(fp, "-%s", fmt.string);
      }
    }
    fprintf(fp, "\n");
  }
}

/***************************************************************************
 * remove leading/trailing whitespace
 ***************************************************************************/
static void trim(char *line, size_t sizeof_line) {
  if (sizeof_line > strlen(line)) {
    sizeof_line = strlen(line);
  }

  while (isspace(*line & 0xFF) && sizeof_line > 0) {
    memmove(line, line + 1, sizeof_line - 1);
    sizeof_line--;
  }
  line[sizeof_line] = '\0';
  while (*line && isspace(line[sizeof_line - 1] & 0xFF)) {
    line[--sizeof_line] = '\0';
  }
}

/***************************************************************************
 ***************************************************************************/
void masscan_read_config_file(struct Masscan *masscan, const char *filename) {
  FILE *fp = NULL;
  errno_t err;
  char line[65536];

  err = fopen_s(&fp, filename, "rt");
  if (err || fp == NULL) {
    char dir[512];
    LOG(LEVEL_ERROR, "%s: %s\n", filename, strerror(errno));
    if (getcwd(dir, sizeof(dir)) == NULL) {
      LOG(LEVEL_ERROR, "cwd = <unknown>\n");
    } else {
      LOG(LEVEL_ERROR, "cwd = %s\n", dir);
    }
    exit(1);
  }

  while (fgets(line, sizeof(line), fp)) {
    char *name;
    char *value;

    trim(line, sizeof(line));

    if (ispunct(line[0] & 0xFF) || line[0] == '\0') {
      continue;
    }

    name = line;
    value = strchr(line, '=');
    if (value == NULL)
      continue;
    *value = '\0';
    value++;
    trim(name, sizeof(line));
    trim(value, sizeof(line));

    masscan_set_parameter(masscan, name, value);
  }

  fclose(fp);
}

/***************************************************************************
 ***************************************************************************/
int masscan_conf_contains(const char *x, int argc, char **argv) {
  int i;

  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], x) == 0)
      return 1;
  }

  return 0;
}

/***************************************************************************
 ***************************************************************************/
int mainconf_selftest() {

  char test1[] = " test 1 ";
  char test2[] = " test 2 ";
  char test3[] = " test 3 ";
  char test4[] = " ";
  char test5[] = "";
  char test6[] = "\0\0\0\0";

  trim(test1, sizeof(test1));
  if (strcmp(test1, "test 1") != 0) {
    return 1; /* failure */
  }
  trim(test2, 6);
  if (strcmp(test2, "test") != 0) {
    return 1; /* failure */
  }
  trim(test3, 7);
  if (strcmp(test3, "test 3") != 0) {
    return 1; /* failure */
  }
  trim(test4, 1);
  if (strcmp(test4, "") != 0) {
    return 1; /* failure */
  }
  trim(test5, 0);
  if (strcmp(test5, "") != 0) {
    return 1; /* failure */
  }
  trim(test6, sizeof(test6));
  if (strcmp(test6, "") != 0) {
    return 1; /* failure */
  }

  {
    struct Range range;

    range.begin = 16;
    range.end = 32 - 1;
    if (count_cidr_bits(range) != 28) {
      return 1;
    }

    range.begin = 1;
    range.end = 13;
    if (count_cidr_bits(range) != 0) {
      return 1;
    }
  }

  {
    struct Range6 range;

    range.begin.hi = 0x20010db800000000;
    range.begin.lo = 0x0000000000000000;
    range.end.hi = 0x20010db800000000;
    range.end.lo = 0x000003ffffffffff;
    if (count_cidr6_bits(&range) != 86) {
      return 1;
    }

    range.begin.hi = 0x20010db800000000;
    range.begin.lo = 0x0000000000000000;
    range.end.hi = 0x20010db80007ffff;
    range.end.lo = 0xffffffffffffffff;
    if (count_cidr6_bits(&range) != 45) {
      return 1;
    }

    range.begin.hi = 0x20010db800000000;
    range.begin.lo = 0x0000000000000001;
    range.end.hi = 0x20010db80007ffff;
    range.end.lo = 0xffffffffffffffff;
    if (count_cidr6_bits(&range) != 0) {
      return 1;
    }
  }

  /* */
  {
    int argc = 6;
    char *argv[] = {"foo", "bar", "-ddd", "--readscan", "xxx", "--something"};

    if (masscan_conf_contains("--nothing", argc, argv))
      return 1;

    if (!masscan_conf_contains("--readscan", argc, argv))
      return 1;
  }

  return 0;
}
