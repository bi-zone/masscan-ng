#ifndef PROTO_DNS_PARSE_H
#define PROTO_DNS_PARSE_H

struct DomainPointer {
  unsigned char *name;
  size_t length;
  size_t max_length;
};

struct DNS_Incoming {
  unsigned id; /* transaction id */
  unsigned is_valid : 1;
  unsigned is_formerr : 1;
  unsigned is_edns0 : 1; /* edns0 features found */
  unsigned qr : 1;       /* 'query' or 'response' */
  unsigned aa : 1;       /* 'authoritative answer' */
  unsigned tc : 1;       /* 'truncation' */
  unsigned rd : 1;       /* 'recursion desired' */
  unsigned ra : 1;       /* 'recursion available' */
  unsigned z : 3;        /* reserved */
  unsigned opcode;
  unsigned rcode; /* response error code */
  size_t qdcount; /* query count */
  size_t ancount; /* answer count */
  size_t nscount; /* name-server/authority count */
  size_t arcount; /* additional record count */
  struct {
    unsigned payload_size;
    unsigned version;
    unsigned z;
  } edns0;
  const unsigned char *req;
  size_t req_length;

  /* the query name */
  struct DomainPointer query_name;
  unsigned query_type;
  unsigned char query_name_buffer[256];

  size_t rr_count;
  size_t rr_offset[1024];
  size_t edns0_offset;
};

void proto_dns_parse(struct DNS_Incoming *dns, const unsigned char px[],
                     size_t offset, size_t max);
size_t dns_name_skip(const unsigned char px[], size_t offset, size_t max);

#endif
