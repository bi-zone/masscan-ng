#ifndef OUTPUT_H
#define OUTPUT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "masscan-app.h"
#include "masscan-status.h"
#include "masscan.h"
#include "massip-addr.h"
#include "pixie-threads.h"
#include "stack-src.h"
#include "util-cross.h"

struct Masscan;
struct Output;
enum ApplicationProtocol;
enum PortStatus;

/**
 * Output plugins
 *
 * The various means for writing output are essentially plugins. As new methods
 * are created, we just fill in a structure of function pointers.
 * TODO: this needs to be a loadable DLL, but in the meantime, it's just
 * internal structures.
 */
struct OutputType {
  const char *file_extension;
  void *(*create)(struct Output *out);
  void (*open)(struct Output *out);
  void (*close)(struct Output *out);
  void (*status)(struct Output *out, time_t timestamp, enum PortStatus status,
                 const ipaddress *ip, unsigned ip_proto, unsigned port,
                 unsigned reason, unsigned ttl);
  void (*banner)(struct Output *out, time_t timestamp, const ipaddress *ip,
                 unsigned ip_proto, unsigned port,
                 enum ApplicationProtocol proto, unsigned ttl,
                 const unsigned char *px, size_t length);
  void (*sign)(struct Output *out, time_t timestamp, const ipaddress *ip,
               unsigned ip_proto, unsigned port,
               enum ApplicationProtocol proto);
};

/* Masscan creates one "output" structure per thread. */
struct Output {
  const struct Masscan *masscan;
  char *filename;
  char *filename_ssl_keys;
  FILE *fp;
  FILE *fp_ssl_keys;

  struct stack_src_t src[8];
  const struct OutputType *funcs;
  enum OutputFormat format;

  /* The timestamp when this scan started. This is preserved in output files
   * because that's what nmap does, and a lot of tools parse this. */
  time_t when_scan_started;

  /* Whether we've started writing to a file yet. We are lazy writing
   * the file header until we've actually go something to write */
  unsigned is_virgin_file : 1;

  /* used by json output to test if the first record has been seen, in order
   * to determine if it needs a , comma before the record */
  unsigned is_first_record_seen : 1;

  struct {
    time_t next;
    time_t last;
    time_t period;
    time_t offset;
    uint64_t filesize;
    uint64_t bytes_written;
    unsigned filecount; /* filesize rotates */
    char *directory;
  } rotate;

  unsigned is_banner : 1;
  unsigned is_gmt : 1;         /* --gmt */
  unsigned is_interactive : 1; /* echo to command line */
  unsigned is_show_open : 1;   /* show open ports (default) */
  unsigned is_show_closed : 1; /* show closed ports */
  unsigned is_show_host : 1;   /* show host status info, like up/down */
  unsigned is_append : 1;      /* append to file */
  struct {
    struct {
      uint64_t open;
      uint64_t closed;
      uint64_t banner;
    } tcp;
    struct {
      uint64_t open;
      uint64_t closed;
    } udp;
    struct {
      uint64_t open;
      uint64_t closed;
    } sctp;
    struct {
      uint64_t echo;
      uint64_t timestamp;
    } icmp;
    struct {
      uint64_t open;
    } arp;
    struct {
      uint64_t open;
      uint64_t closed;
    } oproto;
  } counts;

  struct {
    ipaddress ip;
    unsigned port;
    ptrdiff_t fd;
    uint64_t outstanding;
    size_t state;
  } redis;
  struct {
    char *stylesheet;
  } xml;
};

const char *name_from_ip_proto(unsigned ip_proto);
const char *status_string(enum PortStatus x);
const char *reason_string(int x, char *buffer, size_t sizeof_buffer);
const char *normalize_string(const unsigned char *px, size_t length, char *buf,
                             size_t buf_len);

extern const struct OutputType text_output;
extern const struct OutputType unicornscan_output;
extern const struct OutputType xml_output;
extern const struct OutputType json_output;
extern const struct OutputType ndjson_output;
extern const struct OutputType certs_output;
extern const struct OutputType binary_output;
extern const struct OutputType null_output;
extern const struct OutputType redis_output;
extern const struct OutputType hostonly_output;
extern const struct OutputType grepable_output;

/* Creates an "output" object. This is called by the receive thread in order
 * to send "status" information (open/closed ports) and "banners" to either
 * the command-line or to files in specific formats, such as XML or Redis
 * @param masscan
 *      The master configuration.
 * @param thread_index
 *      When there are more than one receive threads, they are differentiated
 *      by this index number.
 * @return
 *      an output object that must eventually be destroyed by output_destroy().
 */
struct Output *output_create(const struct Masscan *masscan, size_t index,
                             size_t sub_index);
void output_destroy(struct Output *output);

typedef void (*OUTPUT_REPORT_SIGN)(struct Output *output, time_t timestamp,
                                   const ipaddress *ip, unsigned ip_proto,
                                   unsigned port,
                                   enum ApplicationProtocol app_proto);

void output_report_sign(struct Output *output, time_t timestamp,
                        const ipaddress *ip, unsigned ip_proto, unsigned port,
                        enum ApplicationProtocol app_proto);

typedef void (*OUTPUT_REPORT_STATUS)(struct Output *output, time_t timestamp,
                                     enum PortStatus status,
                                     const ipaddress *ip, unsigned ip_proto,
                                     unsigned port, unsigned reason,
                                     unsigned ttl, const unsigned char mac[6]);

void output_report_status(struct Output *output, time_t timestamp,
                          enum PortStatus status, const ipaddress *ip,
                          unsigned ip_proto, unsigned port, unsigned reason,
                          unsigned ttl, const unsigned char mac[6]);

typedef void (*OUTPUT_REPORT_BANNER)(struct Output *output, time_t timestamp,
                                     const ipaddress *ip, unsigned ip_proto,
                                     unsigned port,
                                     enum ApplicationProtocol proto,
                                     unsigned ttl, const unsigned char *px,
                                     size_t length);

void output_report_banner(struct Output *output, time_t timestamp,
                          const ipaddress *ip, unsigned ip_proto, unsigned port,
                          enum ApplicationProtocol app_proto, unsigned ttl,
                          const unsigned char *px, size_t length);

typedef void (*OUTPUT_SSL_KEY)(struct Output *output, const char *line);

void output_ssl_key(struct Output *output, const char *line);

/* Regression tests this unit.
 * @return
 *      0 on success, or positive integer on failure */
int output_selftest(void);

#endif
