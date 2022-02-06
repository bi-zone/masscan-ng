#include <assert.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "logger.h"
#include "util-openssl.h"

char *ipaddr_to_asc(unsigned char *p, int len) {
  /*
   * 40 is enough space for the longest IPv6 address + nul terminator byte
   * XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX\0
   */
  char buf[40], *out;
  ptrdiff_t i = 0, bytes = 0;
  size_t remain = 0;

  switch (len) {
  case 4: /* IPv4 */
    BIO_snprintf(buf, sizeof(buf), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    break;
    /* TODO possibly combine with static i2r_address() in v3_addr.c */
  case 16: /* IPv6 */
    for (out = buf, i = 8, remain = sizeof(buf); i-- > 0 && bytes >= 0;
         remain -= bytes, out += bytes) {
      const char *template = (i > 0 ? "%X:" : "%X");

      bytes = (ptrdiff_t)BIO_snprintf(out, remain, template, p[0] << 8 | p[1]);
      p += 2;
    }
    break;
  default:
    BIO_snprintf(buf, sizeof(buf), "<invalid length=%d>", len);
    break;
  }
  return OPENSSL_strdup(buf);
}

int nid_id_on_SmtpUTF8Mailbox = NID_undef;
int nid_XmppAddr = NID_undef;
int nid_SRVName = NID_undef;
int nid_NAIRealm = NID_undef;
int nid_KRB5PrincipalName = NID_undef;
int nid_DomainController = NID_undef;
int nid_CiscoDlswTConnOperTable = NID_undef;
int nid_AttributeSyntaxVendor = NID_undef;

int add_ext_obj(const char *oid, const char *sn, const char *ln) {
  int res;
  res = OBJ_txt2nid(oid);
  if (res != NID_undef) {
    return res;
  }
  res = OBJ_create(oid, sn, ln);
  return res;
}

void init_openssl_ext_obj() {
  nid_id_on_SmtpUTF8Mailbox =
      add_ext_obj(OID_id_on_SmtpUTF8Mailbox, SN_id_on_SmtpUTF8Mailbox,
                  LN_id_on_SmtpUTF8Mailbox);
  assert(nid_id_on_SmtpUTF8Mailbox != NID_undef);
  nid_XmppAddr = add_ext_obj(OID_XmppAddr, SN_XmppAddr, LN_XmppAddr);
  assert(nid_XmppAddr != NID_undef);
  nid_SRVName = add_ext_obj(OID_SRVName, SN_SRVName, LN_SRVName);
  assert(nid_SRVName != NID_undef);
  nid_NAIRealm = add_ext_obj(OID_NAIRealm, SN_NAIRealm, LN_NAIRealm);
  assert(nid_NAIRealm != NID_undef);
  nid_KRB5PrincipalName = add_ext_obj(
      OID_KRB5PrincipalName, SN_KRB5PrincipalName, LN_KRB5PrincipalName);
  assert(nid_KRB5PrincipalName != NID_undef);
  nid_DomainController = add_ext_obj(OID_DomainController, SN_DomainController,
                                     LN_DomainController);
  assert(nid_DomainController != NID_undef);
  nid_CiscoDlswTConnOperTable =
      add_ext_obj(OID_CiscoDlswTConnOperTable, SN_CiscoDlswTConnOperTable,
                  LN_CiscoDlswTConnOperTable);
  assert(nid_CiscoDlswTConnOperTable != NID_undef);
  nid_AttributeSyntaxVendor =
      add_ext_obj(OID_AttributeSyntaxVendor, SN_AttributeSyntaxVendor,
                  LN_AttributeSyntaxVendor);
  assert(nid_AttributeSyntaxVendor != NID_undef);
}

int GENERAL_NAME_simple_print(BIO *out, GENERAL_NAME *gen) {
  char *tmp;
  int nid;
  int ret = -2;

  switch (gen->type) {
  case GEN_OTHERNAME:
    nid = OBJ_obj2nid(gen->d.otherName->type_id);
    switch (nid) {
    case NID_ms_upn:
      ret = ASN1_STRING_print_ex(out, gen->d.otherName->value->value.utf8string,
                                 0);
      if (ret < 0) {
        ret = -1;
      } else {
        ret = 1;
      }
      break;
    default:
      if (nid == NID_undef) {
        char sz_obj[256];
        int len_sz_obj;
        len_sz_obj =
            OBJ_obj2txt(sz_obj, sizeof(sz_obj), gen->d.otherName->type_id, 0);
        LOG(LEVEL_WARNING,
            "[GENERAL_NAME_simple_print] unknown GEN_OTHERNAME oid %d(%.*s)\n",
            nid, len_sz_obj, sz_obj);
      } else if (nid == nid_XmppAddr || nid == nid_NAIRealm ||
                 nid == nid_id_on_SmtpUTF8Mailbox) {
        ret = ASN1_STRING_print_ex(
            out, gen->d.otherName->value->value.utf8string, 0);
        if (ret < 0) {
          ret = -1;
        } else {
          ret = 1;
        }
      } else if (nid == nid_SRVName || nid == nid_AttributeSyntaxVendor) {
        ret = ASN1_STRING_print_ex(out,
                                   gen->d.otherName->value->value.ia5string, 0);
        if (ret < 0) {
          ret = -1;
        } else {
          ret = 1;
        }
      } else if (nid == nid_KRB5PrincipalName || nid == nid_DomainController ||
                 nid == nid_CiscoDlswTConnOperTable || nid == NID_description ||
                 nid == NID_id_on_permanentIdentifier ||
                 nid == NID_organizationName) {
        char sz_obj[256];
        int len_sz_obj;
        len_sz_obj =
            OBJ_obj2txt(sz_obj, sizeof(sz_obj), gen->d.otherName->type_id, 0);
        LOG(LEVEL_INFO,
            "[GENERAL_NAME_simple_print] unknown GEN_OTHERNAME oid %d(%.*s)\n",
            nid, len_sz_obj, sz_obj);
      } else {
        char sz_obj[256];
        int len_sz_obj;
        len_sz_obj =
            OBJ_obj2txt(sz_obj, sizeof(sz_obj), gen->d.otherName->type_id, 0);
        LOG(LEVEL_WARNING,
            "[GENERAL_NAME_simple_print] unknown GEN_OTHERNAME oid %d(%.*s)\n",
            nid, len_sz_obj, sz_obj);
      }
      break;
    }
    break;
  case GEN_DNS:
  case GEN_EMAIL:
  case GEN_URI:
    ret = ASN1_STRING_print_ex(out, gen->d.ia5, 0);
    if (ret < 0) {
      ret = -1;
    } else {
      ret = 1;
    }
    break;
  case GEN_DIRNAME:
    ret = X509_NAME_print_ex(out, gen->d.dirn, 0, XN_FLAG_ONELINE);
    if (ret != 1) {
      ret = -1;
    }
    break;
  case GEN_IPADD:
    tmp = ipaddr_to_asc(gen->d.ip->data, gen->d.ip->length);
    if (tmp == NULL)
      return -1;
    ret = BIO_printf(out, "%s", tmp);
    if (ret < 0) {
      ret = -1;
    } else {
      ret = 1;
    }
    OPENSSL_free(tmp);
    break;
  case GEN_RID:
    ret = i2a_ASN1_OBJECT(out, gen->d.rid);
    if (ret < 0) {
      ret = -1;
    } else {
      ret = 1;
    }
    break;
  default:
    LOG(LEVEL_WARNING, "[GENERAL_NAME_simple_print] unknown type %d",
        gen->type);
  }

  return ret;
}

int util_openssl_selftest() {

  int res;
  res = OBJ_txt2nid("1.3.6.1.5.5.7.8.5");
  if (res == NID_undef) {
    LOG(LEVEL_ERROR, "NID for XmppAddr not defined\n");
    return 1;
  }

  res = OBJ_txt2nid("1.3.6.1.4.1.311.25.1");
  if (res == NID_undef) {
    LOG(LEVEL_ERROR, "NID for MS Domain Controller not defined\n");
    return 1;
  }

  return 0;
}