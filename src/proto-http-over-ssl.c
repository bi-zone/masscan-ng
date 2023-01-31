#include "proto-http-over-ssl.h"
#include "logger.h"
#include "masscan-app.h"
#include "pixie-timer.h"
#include "proto-http.h"
#include "proto-interactive.h"
#include "proto-keyout.h"
#include "proto-ssl.h"
#include "proto-tcp.h"
#include "siphash24.h"
#include "string_s.h"
#include "util-cross.h"
#include "util-malloc.h"
#include "util-openssl.h"
#include "util-test.h"

#include <assert.h>
#include <ctype.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static void BANNER_VERSION(struct BannerOutput *banout, SSL *ssl) {
  char foo[64];
  int version = SSL_version(ssl);

  switch (version) {
  case SSL3_VERSION:
    banout_append(banout, PROTO_SSL3, "SSLv3 ", AUTO_LEN);
    banout_append(banout, PROTO_VULN, "SSL[v3] ", AUTO_LEN);
    break;
  case TLS1_VERSION:
    banout_append(banout, PROTO_SSL3, "TLS/1.0 ", AUTO_LEN);
    break;
  case TLS1_1_VERSION:
    banout_append(banout, PROTO_SSL3, "TLS/1.1 ", AUTO_LEN);
    break;
  case TLS1_2_VERSION:
    banout_append(banout, PROTO_SSL3, "TLS/1.2 ", AUTO_LEN);
    break;
  case TLS1_3_VERSION:
    banout_append(banout, PROTO_SSL3, "TLS/1.3 ", AUTO_LEN);
    break;
  default:
    sprintf_s(foo, sizeof(foo), "SSLver[%u,%u] ",
              (unsigned)((version >> 8) & 0xFF), (unsigned)(version & 0xFF));
    banout_append(banout, PROTO_SSL3, foo, strlen(foo));
  }
}

static void BANNER_CIPHER(struct BannerOutput *banout, SSL *ssl) {
  char foo[64];

  const SSL_CIPHER *ssl_cipher;
  uint16_t cipher_suite;

  ssl_cipher = SSL_get_current_cipher(ssl);
  if (ssl_cipher == NULL) {
    ssl_cipher = SSL_get_pending_cipher(ssl);
    if (ssl_cipher == NULL) {
      return;
    }
  }

  cipher_suite = SSL_CIPHER_get_protocol_id(ssl_cipher);
  sprintf_s(foo, sizeof(foo), "cipher:0x%x", cipher_suite);
  banout_append(banout, PROTO_SSL3, foo, AUTO_LEN);
}

static void BANNER_CERTS(struct BannerOutput *banout, SSL *ssl) {
  STACK_OF(X509) * sk_x509_certs;
  int i_cert;
  int res;
  char s_base64[512];

  sk_x509_certs = SSL_get_peer_cert_chain(ssl);
  if (sk_x509_certs == NULL) {
    return;
  }
  for (i_cert = 0; i_cert < sk_X509_num(sk_x509_certs); i_cert++) {
    X509 *x509_cert = NULL;
    BIO *bio_base64 = NULL;
    BIO *bio_mem = NULL;

    x509_cert = sk_X509_value(sk_x509_certs, i_cert);
    if (x509_cert == NULL) {
      LOG(LEVEL_WARNING, "[BANNER_CERTS]sk_X509_value failed on %d\n", i_cert);
      continue;
    }

    bio_base64 = BIO_new(BIO_f_base64());
    if (bio_base64 == NULL) {
      LOG(LEVEL_WARNING, "[BANNER_CERTS]BIO_new(base64) failed on %d\n",
          i_cert);
      continue;
    }
    BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);

    bio_mem = BIO_new(BIO_s_mem());
    if (bio_mem == NULL) {
      LOG(LEVEL_WARNING, "[BANNER_CERTS]BIO_new(bio_mem) failed on %d\n",
          i_cert);
      BIO_free(bio_base64);
      continue;
    }
    bio_base64 = BIO_push(bio_base64, bio_mem);

    res = i2d_X509_bio(bio_base64, x509_cert);
    if (res != 1) {
      LOG(LEVEL_WARNING,
          "[BANNER_CERTS]i2d_X509_bio failed with error %d on %d\n", res,
          i_cert);
      BIO_free(bio_mem);
      BIO_free(bio_base64);
      continue;
    }
    res = BIO_flush(bio_base64);
    if (res != 1) {
      LOG(LEVEL_WARNING, "[BANNER_CERTS]BIO_flush failed with error %d on %d\n",
          res, i_cert);
      BIO_free(bio_mem);
      BIO_free(bio_base64);
      continue;
    }

    while (true) {
      res = BIO_read(bio_mem, s_base64, sizeof(s_base64));
      if (res > 0) {
        banout_append(banout, PROTO_X509_CERT, s_base64, (size_t)res);
      } else if (res == 0 || res == -1) {
        break;
      } else {
        LOG(LEVEL_WARNING, "[BANNER_CERTS]BIO_read failed with error: %d\n",
            res);
        LOGopenssl(LEVEL_WARNING);
        break;
      }
    }
    banout_end(banout, PROTO_X509_CERT);
    BIO_free(bio_mem);
    BIO_free(bio_base64);
  }
  return;
}

static void BANNER_NAMES(struct BannerOutput *banout, SSL *ssl) {
  int res;
  char s_names[512];
  BIO *bio = NULL;
  X509 *x509_cert = NULL;
  X509_NAME *x509_subject_name = NULL;
  STACK_OF(GENERAL_NAME) *x509_alt_names = NULL;

  x509_cert = SSL_get_peer_certificate(ssl);
  if (x509_cert == NULL) {
    goto error0;
  }

  bio = BIO_new(BIO_s_mem());
  if (bio == NULL) {
    LOG(LEVEL_WARNING, "[BANNER_NAMES]BIO_new failed\n");
    goto error1;
  }

  x509_subject_name = X509_get_subject_name(x509_cert);
  if (x509_subject_name != NULL) {
    int i_name;
    /*res = X509_NAME_print_ex(bio, x509_subject_name, 0, 0);
    if(res != 1) {
            LOG(LEVEL_WARNING, "[BANNER_NAMES]X509_get_subject_name failed with
    error %d\n", res);
    }*/
    for (i_name = 0; i_name < X509_NAME_entry_count(x509_subject_name);
         i_name++) {
      X509_NAME_ENTRY *name_entry = NULL;
      ASN1_OBJECT *fn = NULL;
      ASN1_STRING *val = NULL;

      name_entry = X509_NAME_get_entry(x509_subject_name, i_name);
      if (name_entry == NULL) {
        LOG(LEVEL_WARNING, "[BANNER_NAMES]X509_NAME_get_entry failed on %d\n",
            i_name);
        continue;
      }
      fn = X509_NAME_ENTRY_get_object(name_entry);
      if (fn == NULL) {
        LOG(LEVEL_WARNING,
            "[BANNER_NAMES]X509_NAME_ENTRY_get_object failed on %d\n", i_name);
        continue;
      }
      val = X509_NAME_ENTRY_get_data(name_entry);
      if (val == NULL) {
        LOG(LEVEL_WARNING,
            "[BANNER_NAMES]X509_NAME_ENTRY_get_data failed on %d\n", i_name);
        continue;
      }
      if (NID_commonName == OBJ_obj2nid(fn)) {
        BIO_printf(bio, ", ");
        res = ASN1_STRING_print_ex(bio, val, 0);
        if (res < 0) {
          LOG(LEVEL_WARNING,
              "[BANNER_NAMES]ASN1_STRING_print_ex failed with error %d on %d\n",
              res, i_name);
          BIO_printf(bio, "<can't get cn>");
        }
      }
    }
  } else {
    LOG(LEVEL_WARNING, "[BANNER_NAMES]X509_get_subject_name failed\n");
  }

  x509_alt_names =
      X509_get_ext_d2i(x509_cert, NID_subject_alt_name, NULL, NULL);
  if (x509_alt_names != NULL) {
    int i_name = 0;
    for (i_name = 0; i_name < sk_GENERAL_NAME_num(x509_alt_names); i_name++) {
      GENERAL_NAME *x509_alt_name;

      x509_alt_name = sk_GENERAL_NAME_value(x509_alt_names, i_name);
      if (x509_alt_name == NULL) {
        LOG(LEVEL_WARNING, "[BANNER_NAMES]sk_GENERAL_NAME_value failed on %d\n",
            i_name);
        continue;
      }
      BIO_printf(bio, ", ");
      res = GENERAL_NAME_simple_print(bio, x509_alt_name);
      if (res < 0) {
        LOG(LEVEL_DEBUG,
            "[BANNER_NAMES]GENERAL_NAME_simple_print failed with error %d on "
            "%d\n",
            res, i_name);
        BIO_printf(bio, "<can't get alt>");
      }
    }
    sk_GENERAL_NAME_pop_free(x509_alt_names, GENERAL_NAME_free);
  }

  while (true) {
    res = BIO_read(bio, s_names, sizeof(s_names));
    if (res > 0) {
      banout_append(banout, PROTO_SSL3, s_names, (size_t)res);
    } else if (res == 0 || res == -1) {
      break;
    } else {
      LOG(LEVEL_WARNING, "[BANNER_NAMES]BIO_read failed with error: %d\n", res);
      LOGopenssl(LEVEL_WARNING);
      break;
    }
  }

  // error2:
  BIO_free(bio);
error1:
  X509_free(x509_cert);
error0:
  return;
}

void ssl_keylog_callback(const SSL *ssl, const char *line) {
  struct KeyOutput **keyout = (struct KeyOutput **)SSL_get_ex_data(ssl, 1);
  if (keyout == NULL || line == NULL) {
    return;
  }
  keyout_new_line(keyout, line);
}

void ssl_info_callback(const SSL *ssl, int where, int ret) {
  struct BannerOutput *banout = (struct BannerOutput *)SSL_get_ex_data(ssl, 0);
  if (banout == NULL) {
    return;
  }
  if (where & SSL_CB_ALERT) {
    char foo[64];
    sprintf_s(foo, sizeof(foo), " ALERT(0x%04x) ", ret);
    banout_append(banout, PROTO_SSL3, foo, AUTO_LEN);
  }
}

enum {
  OPENSSL_HANDSHAKE,
  OPENSSL_APP_HELLO,
  OPENSSL_APP_RECEIVE_NEXT,
  OPENSSL_APP_CLOSE,
  OPENSSL_UNKNOWN
};

static void
ssl_parse_record(const struct Banner1 *banner1, void *banner1_private,
                 struct ProtocolState *pstate,
                 struct ResendPayload *resend_payload, const unsigned char *px,
                 size_t length, struct BannerOutput *banout,
                 struct SignOutput *signout, struct KeyOutput **keyout,
                 struct InteractiveData *more) {
  size_t state = pstate->state;
  int res, res_ex;
  int is_continue;

  UNUSEDPARM(banner1_private);
  assert(banner1->ssl_ctx != NULL);
  assert(pstate->parser_stream == &banner_http_over_ssl);

  if (state == OPENSSL_UNKNOWN) {
    is_continue = 0;
  } else {
    is_continue = 1;
  }

  if (is_continue && px != NULL && length != 0) {
    size_t offset = 0;
    uint64_t now_time = pixie_gettime();
    res = 0;
    while (offset < length) {
      res = BIO_write(pstate->sub.ssl_dynamic.rbio, px + offset,
                      (unsigned int)min(16384, length - offset));
      LOG(LEVEL_INFO, "[ssl_parse_record]BIO_write: %d \n", res);
      if (res > 0) {
        offset += (size_t)res;
        continue;
      } else {
        LOG(LEVEL_WARNING,
            "[ssl_parse_record]BIO_write failed with error: %d\n", res);
        switch_application_proto(banner1, pstate, resend_payload, banout,
                                 keyout, PROTO_SSL3, &banner_ssl);
        application_receive_next(banner1, pstate, pstate, resend_payload,
                                 px + offset, length - offset, banout, signout,
                                 keyout, more);
        return;
      }
    }
    now_time = pixie_gettime() - now_time;
    if (length > 16384 || now_time > 1000000) {
      LOGip(LEVEL_WARNING, &pstate->ip, pstate->port,
            "[ssl_parse_record]len px: 0x%" PRIxPTR ", time: " PRIu64
            " millis\n",
            length, now_time * 1000);
      LOG(LEVEL_WARNING, "[ssl_parse_record]offset: 0x%" PRIxPTR ", res = %d\n",
          offset, res);
      if (length > 3) {
        LOG(LEVEL_WARNING, "[ssl_parse_record]dump: %02X %02X %02X %02X\n",
            px[0], px[1], px[2], px[3]);
      }
    }
  }

  while (is_continue) {
    switch (state) {
    case OPENSSL_HANDSHAKE:
      res = SSL_do_handshake(pstate->sub.ssl_dynamic.ssl);
      res_ex = SSL_ERROR_NONE;
      if (res < 0) {
        res_ex = SSL_get_error(pstate->sub.ssl_dynamic.ssl, res);
      }
      pstate->sub.ssl_dynamic.handshake_state =
          SSL_get_state(pstate->sub.ssl_dynamic.ssl);
      if (pstate->sub.ssl_dynamic.have_dump_version == false &&
          pstate->sub.ssl_dynamic.handshake_state != TLS_ST_BEFORE &&
          pstate->sub.ssl_dynamic.handshake_state != TLS_ST_CW_CLNT_HELLO &&
          (SSL_get_current_cipher(pstate->sub.ssl_dynamic.ssl) ||
           SSL_get_pending_cipher(pstate->sub.ssl_dynamic.ssl))) {
        BANNER_VERSION(banout, pstate->sub.ssl_dynamic.ssl);
        BANNER_CIPHER(banout, pstate->sub.ssl_dynamic.ssl);
        pstate->sub.ssl_dynamic.have_dump_version = true;
      }
      if (pstate->sub.ssl_dynamic.have_dump_cert == false &&
          SSL_get_peer_cert_chain(pstate->sub.ssl_dynamic.ssl) != NULL) {
        if (banner1->is_capture_cert) {
          BANNER_CERTS(banout, pstate->sub.ssl_dynamic.ssl);
        }
        BANNER_NAMES(banout, pstate->sub.ssl_dynamic.ssl);
        pstate->sub.ssl_dynamic.have_dump_cert = true;
      }

      if (res == 1) {
        if (pstate->sub.ssl_dynamic.handshake_state == TLS_ST_OK) {
          struct ProtocolState *psub_state = pstate->sub.ssl_dynamic.psub_state;
          psub_state->app_proto = PROTO_HTTPS;
          psub_state->parser_stream = &banner_http;
          init_application_proto(banner1, psub_state, resend_payload, banout,
                                 keyout);
          state = OPENSSL_APP_HELLO;
        } else {
          LOG(LEVEL_WARNING, "Unknown handshake state %d\n",
              pstate->sub.ssl_dynamic.handshake_state);
          state = OPENSSL_UNKNOWN;
        }
      } else if (res < 0 && res_ex == SSL_ERROR_WANT_READ) {
        size_t offset = 0;
        while (true) {
          if (pstate->sub.ssl_dynamic.data_max_len - offset <= 0) {
            unsigned char *tmp_data = NULL;
            tmp_data = (unsigned char *)realloc(
                pstate->sub.ssl_dynamic.data,
                pstate->sub.ssl_dynamic.data_max_len * 2);
            if (tmp_data == NULL) {
              LOG(LEVEL_WARNING,
                  "[ssl_parse_record]SSL realoc memory error 0x%" PRIxPTR "\n",
                  pstate->sub.ssl_dynamic.data_max_len * 2);
              state = OPENSSL_UNKNOWN;
              break;
            } else {
              pstate->sub.ssl_dynamic.data = tmp_data;
              pstate->sub.ssl_dynamic.data_max_len =
                  pstate->sub.ssl_dynamic.data_max_len * 2;
            }
          }

          res = BIO_read(
              pstate->sub.ssl_dynamic.wbio,
              pstate->sub.ssl_dynamic.data + offset,
              (unsigned int)(pstate->sub.ssl_dynamic.data_max_len - offset));
          if (res > 0) {
            LOG(LEVEL_INFO, "[ssl_parse_record]BIO_read: %d\n", res);
            offset += (size_t)res;
          } else if (res == 0 || res == -1) {
            LOG(LEVEL_INFO, "[ssl_parse_record]BIO_read: %d\n", res);
            break;
          } else {
            LOG(LEVEL_WARNING,
                "[ssl_parse_record]BIO_read failed with error: %d\n", res);
            LOGopenssl(LEVEL_WARNING);
            state = OPENSSL_UNKNOWN;
            break;
          }
        }
        if (state != OPENSSL_UNKNOWN) {
          tcp_transmit(more, pstate->sub.ssl_dynamic.data, offset, 0);
          is_continue = 0;
        }
      } else {
        LOG(LEVEL_DEBUG,
            "[ssl_parse_record]SSL_do_handshake failed with error: %d, "
            "ex_error: %d\n",
            res, res_ex);
        LOGopenssl(LEVEL_DEBUG);
        state = OPENSSL_UNKNOWN;
      }
      break;
    case OPENSSL_APP_HELLO: {
      struct ProtocolState *psub_state = pstate->sub.ssl_dynamic.psub_state;
      struct InteractiveData sub_more = {0};
      application_receive_hello(banner1, psub_state, resend_payload, banout,
                                keyout, &sub_more);
      assert(sub_more.m_payload != NULL && sub_more.m_length != 0);
      res = 1;
      if (sub_more.m_payload != NULL && sub_more.m_length != 0) {
        res = SSL_write(pstate->sub.ssl_dynamic.ssl, sub_more.m_payload,
                        sub_more.m_length);
        free_interactive_data(&sub_more);
      }
      if (res <= 0) {
        res_ex = SSL_get_error(pstate->sub.ssl_dynamic.ssl, res);
        LOG(LEVEL_WARNING, "[ssl_parse_record]SSL_write error: %d %d\n", res,
            res_ex);
        LOGopenssl(LEVEL_WARNING);
        state = OPENSSL_UNKNOWN;
      } else {
        LOG(LEVEL_INFO, "[ssl_parse_record]SSL_write: %d\n", res);
        size_t offset = 0;
        while (true) {
          if (pstate->sub.ssl_dynamic.data_max_len - offset <= 0) {
            unsigned char *tmp_data = NULL;
            tmp_data = (unsigned char *)realloc(
                pstate->sub.ssl_dynamic.data,
                pstate->sub.ssl_dynamic.data_max_len * 2);
            if (tmp_data == NULL) {
              LOG(LEVEL_WARNING,
                  "[ssl_parse_record]SSL realoc memory error 0x%" PRIxPTR "\n",
                  pstate->sub.ssl_dynamic.data_max_len * 2);
              state = OPENSSL_UNKNOWN;
              break;
            } else {
              pstate->sub.ssl_dynamic.data = tmp_data;
              pstate->sub.ssl_dynamic.data_max_len =
                  pstate->sub.ssl_dynamic.data_max_len * 2;
            }
          }

          res = BIO_read(
              pstate->sub.ssl_dynamic.wbio,
              pstate->sub.ssl_dynamic.data + offset,
              (unsigned int)(pstate->sub.ssl_dynamic.data_max_len - offset));
          if (res > 0) {
            LOG(LEVEL_INFO, "[ssl_parse_record]BIO_read: %d\n", res);
            offset += (size_t)res;
          } else if (res == 0 || res == -1) {
            LOG(LEVEL_DEBUG, "[ssl_parse_record]BIO_read: %d\n", res);
            break;
          } else {
            LOG(LEVEL_WARNING,
                "[ssl_parse_record]BIO_read failed with error: %d\n", res);
            LOGopenssl(LEVEL_WARNING);
            state = OPENSSL_UNKNOWN;
            break;
          }
        }
        if (state != OPENSSL_UNKNOWN) {
          state = OPENSSL_APP_RECEIVE_NEXT;
          tcp_transmit(more, pstate->sub.ssl_dynamic.data, offset, 0);
          is_continue = 0;
        }
      }
    } break;
    case OPENSSL_APP_RECEIVE_NEXT:
      while (true) {
        res =
            SSL_read(pstate->sub.ssl_dynamic.ssl, pstate->sub.ssl_dynamic.data,
                     (unsigned int)pstate->sub.ssl_dynamic.data_max_len);
        if (res > 0) {
          struct InteractiveData sub_more = {0};
          struct ProtocolState *psub_state = pstate->sub.ssl_dynamic.psub_state;
          LOG(LEVEL_INFO, "[ssl_parse_record]SSL_read: %d\n", res);
          application_receive_next(banner1, pstate, psub_state, resend_payload,
                                   pstate->sub.ssl_dynamic.data, (size_t)res,
                                   banout, signout, keyout, &sub_more);
          assert(sub_more.m_payload == NULL && sub_more.m_length == 0);
          free_interactive_data(&sub_more);
          continue;
        } else {
          res_ex = SSL_get_error(pstate->sub.ssl_dynamic.ssl, res);
          if (res_ex == SSL_ERROR_WANT_READ) {
            is_continue = 0;
          } else if (res_ex == SSL_ERROR_ZERO_RETURN) {
            state = OPENSSL_APP_CLOSE;
          } else {
            if (res_ex != SSL_ERROR_SSL) {
              LOG(LEVEL_WARNING, "[ssl_parse_record]SSL_read error: %d %d\n",
                  res, res_ex);
              LOGopenssl(LEVEL_WARNING);
            }
            state = OPENSSL_UNKNOWN;
          }
          break;
        }
      }
      break;
    case OPENSSL_APP_CLOSE:
      tcp_close(more);
      is_continue = 0;
      state = OPENSSL_UNKNOWN;
      break;
    case OPENSSL_UNKNOWN:
      switch_application_proto(banner1, pstate, resend_payload, banout, keyout,
                               PROTO_SSL3, &banner_ssl);
      return;
    }
  }

  pstate->state = state;
  return;
}

/*void print_all_chipher_suit(SSL_CTX *ctx) {
        STACK_OF(SSL_CIPHER) *sk_ciphers;
        int i_cipher;

        sk_ciphers = SSL_CTX_get_ciphers(ctx);
        for(i_cipher = 0; i_cipher < sk_SSL_CIPHER_num(sk_ciphers); i_cipher++)
{ const SSL_CIPHER *cipher; cipher = sk_SSL_CIPHER_value(sk_ciphers, i_cipher);
                LOG(
                        LEVEL_WARNING, "0x%X[%d]: %s\n",
SSL_CIPHER_get_protocol_id(cipher), i_cipher, SSL_CIPHER_get_name(cipher));
        }
}*/

static void *ssl_init(struct Banner1 *banner1) {
  int res;
  const SSL_METHOD *meth;
  SSL_CTX *ctx;

  LOG(LEVEL_INFO, "[ssl_init] >>>\n");

  meth = TLS_method();
  if (meth == NULL) {
    LOG(LEVEL_WARNING, "TLS_method error\n");
    LOGopenssl(LEVEL_WARNING);
    goto error2;
  }

  ctx = SSL_CTX_new(meth);
  if (ctx == NULL) {
    LOG(LEVEL_WARNING, "SSL_CTX_new error\n");
    LOGopenssl(LEVEL_WARNING);
    goto error3;
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_set_min_proto_version(ctx, 0);
  SSL_CTX_set_max_proto_version(ctx, 0);
  SSL_CTX_set_security_level(ctx, 0);
  res = SSL_CTX_set_cipher_list(ctx, "ALL:eNULL");
  if (res != 1) {
    LOG(LEVEL_WARNING, "SSL_CTX_set_cipher_list error %d\n", res);
  }
  res = SSL_CTX_set_ciphersuites(
      ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
           "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:"
           "TLS_AES_128_CCM_8_SHA256");
  if (res != 1) {
    LOG(LEVEL_WARNING, "SSL_CTX_set_ciphersuites error %d\n", res);
  }

  if (banner1->is_capture_key) {
    SSL_CTX_set_keylog_callback(ctx, ssl_keylog_callback);
  }

  banner1->ssl_ctx = ctx;
  LOG(LEVEL_INFO, "SUCCESS init dynamic ssl\n");

  return NULL;
  // error4:
  //	SSL_CTX_free(ctx);
error3:
error2:
  // error1:
  return NULL;
}

static void ssl_cleanup(struct Banner1 *banner1) {
  if (banner1->ssl_ctx != NULL) {
    SSL_CTX_free(banner1->ssl_ctx);
    banner1->ssl_ctx = NULL;
  }
  return;
}

static void ssl_transmit_cleanup(const struct Banner1 *banner1,
                                 struct ProtocolState *pstate,
                                 struct ResendPayload *resend_payload) {
  LOG(LEVEL_INFO, "[ssl_cleanup] >>>\n");
  assert(pstate->parser_stream == &banner_http_over_ssl);
  assert(banner1->ssl_ctx != NULL);

  if (pstate->sub.ssl_dynamic.ssl != NULL) {
    SSL_free(pstate->sub.ssl_dynamic.ssl);
    pstate->sub.ssl_dynamic.ssl = NULL;
    pstate->sub.ssl_dynamic.rbio = NULL;
    pstate->sub.ssl_dynamic.wbio = NULL;
  }

  if (pstate->sub.ssl_dynamic.psub_state != NULL) {
    if (banner_http.transmit_cleanup != NULL) {
      banner_http.transmit_cleanup(banner1, pstate->sub.ssl_dynamic.psub_state,
                                   resend_payload);
    }
    free(pstate->sub.ssl_dynamic.psub_state);
    pstate->sub.ssl_dynamic.psub_state = NULL;
  }
  if (pstate->sub.ssl_dynamic.data != NULL) {
    if ((resend_payload->data >= pstate->sub.ssl_dynamic.data) &&
        (resend_payload->data < (pstate->sub.ssl_dynamic.data +
                                 pstate->sub.ssl_dynamic.data_max_len))) {
      unsigned char *newdata = malloc(resend_payload->data_length);
      if (newdata == NULL) {
        LOG(LEVEL_WARNING, "Out of memory\n");
        resend_payload->data = NULL;
        resend_payload->data_length = 0;
        resend_payload->is_dynamic = false;
      } else {
        memcpy((void *)newdata, resend_payload->data,
               resend_payload->data_length);
        resend_payload->data = newdata;
        resend_payload->is_dynamic = true;
      }
    }
    free(pstate->sub.ssl_dynamic.data);
    pstate->sub.ssl_dynamic.data = NULL;
    pstate->sub.ssl_dynamic.data_max_len = 0;
  }
}

static void ssl_transmit_init(const struct Banner1 *banner1,
                              struct ProtocolState *pstate,
                              struct ResendPayload *resend_payload,
                              struct BannerOutput *banout,
                              struct KeyOutput **keyout) {

  BIO *rbio, *wbio;
  SSL *ssl;
  int res;
  unsigned char *data;
  struct ProtocolState *psub_state;
  unsigned int data_max_len = 4096;

  assert(banner1->ssl_ctx != NULL);
  assert(pstate->parser_stream == &banner_http_over_ssl);

  LOG(LEVEL_INFO, "[ssl_transmit_hello] >>>\n");

  if (banner1->ssl_ctx == NULL) {
    goto error0;
  }

  data = (unsigned char *)malloc(data_max_len);
  if (data == NULL) {
    LOG(LEVEL_WARNING, "SSL alloc memory error 0x%X\n", data_max_len);
    goto error1;
  }

  psub_state = (struct ProtocolState *)calloc(1, sizeof(struct ProtocolState));
  if (psub_state == NULL) {
    LOG(LEVEL_WARNING, "SSL alloc memory error 0x%" PRIx64 "\n",
        sizeof(struct ProtocolState));
    goto error2;
  }

  rbio = BIO_new(BIO_s_mem());
  if (rbio == NULL) {
    LOG(LEVEL_WARNING, "BIO_new(read) error\n");
    LOGopenssl(LEVEL_WARNING);
    goto error3;
  }

  wbio = BIO_new(BIO_s_mem());
  if (wbio == NULL) {
    LOG(LEVEL_WARNING, "BIO_new(write) error\n");
    LOGopenssl(LEVEL_WARNING);
    goto error4;
  }

  ssl = SSL_new(banner1->ssl_ctx);
  if (ssl == NULL) {
    LOG(LEVEL_WARNING, "SSL_new error\n");
    LOGopenssl(LEVEL_WARNING);
    goto error5;
  }

  SSL_set_connect_state(ssl);
  SSL_set_bio(ssl, rbio, wbio);

  res = SSL_set_ex_data(ssl, 0, banout);
  if (res != 1) {
    LOG(LEVEL_WARNING, "SSL_set_ex_data banout error\n");
    LOGopenssl(LEVEL_WARNING);
    goto error6;
  }
  if (!banner1->is_capture_key) {
    keyout = NULL;
  }
  res = SSL_set_ex_data(ssl, 1, keyout);
  if (res != 1) {
    LOG(LEVEL_WARNING, "SSL_set_ex_data keyout error\n");
    LOGopenssl(LEVEL_WARNING);
    goto error7;
  }

  SSL_set_info_callback(ssl, ssl_info_callback);

  pstate->sub.ssl_dynamic.handshake_state = TLS_ST_BEFORE;
  pstate->sub.ssl_dynamic.ssl = ssl;
  pstate->sub.ssl_dynamic.rbio = rbio;
  pstate->sub.ssl_dynamic.wbio = wbio;
  pstate->sub.ssl_dynamic.data = data;
  pstate->sub.ssl_dynamic.data_max_len = data_max_len;
  pstate->sub.ssl_dynamic.psub_state = psub_state;

  return;

  // SSL_set_ex_data(ssl, 1, NULL);
error7:
  // SSL_set_ex_data(ssl, 0, NULL);
error6:
  SSL_free(ssl);
  wbio = NULL;
  rbio = NULL;
error5:
  if (wbio != NULL) {
    BIO_free(wbio);
    wbio = NULL;
  }
error4:
  if (rbio != NULL) {
    BIO_free(rbio);
    rbio = NULL;
  }
error3:
  free(psub_state);
error2:
  free(data);
error1:
error0:
  pstate->parser_stream = &banner_ssl;
  pstate->parser_stream->transmit_init(banner1, pstate, resend_payload, banout,
                                       keyout);

  return;
}

static void ssl_transmit_hello(const struct Banner1 *banner1,
                               struct ProtocolState *pstate,
                               struct ResendPayload *resend_payload,
                               struct BannerOutput *banout,
                               struct KeyOutput **keyout,
                               struct InteractiveData *more) {
  int res, res_ex;
  size_t offset = 0;

  assert(banner1->ssl_ctx != NULL);
  assert(pstate->parser_stream == &banner_http_over_ssl);

  res = SSL_do_handshake(pstate->sub.ssl_dynamic.ssl);
  res_ex = SSL_ERROR_NONE;
  if (res < 0) {
    res_ex = SSL_get_error(pstate->sub.ssl_dynamic.ssl, res);
  }

  if (res == 1) {
    // success
  } else if (res < 0 && res_ex == SSL_ERROR_WANT_READ) {
    offset = 0;
    while (true) {
      if (pstate->sub.ssl_dynamic.data_max_len - offset <= 0) {
        unsigned char *tmp_data = NULL;
        tmp_data =
            (unsigned char *)realloc(pstate->sub.ssl_dynamic.data,
                                     pstate->sub.ssl_dynamic.data_max_len * 2);
        if (tmp_data == NULL) {
          LOG(LEVEL_WARNING, "SSL realoc memory error 0x%" PRIxPTR "\n",
              pstate->sub.ssl_dynamic.data_max_len * 2);
          goto error1;
        }
        pstate->sub.ssl_dynamic.data = tmp_data;
        pstate->sub.ssl_dynamic.data_max_len =
            pstate->sub.ssl_dynamic.data_max_len * 2;
      }

      res = BIO_read(pstate->sub.ssl_dynamic.wbio,
                     pstate->sub.ssl_dynamic.data + offset,
                     (int)(pstate->sub.ssl_dynamic.data_max_len - offset));
      if (res > 0) {
        LOG(LEVEL_INFO, "[ssl_transmit_hello]BIO_read: %d\n", res);
        offset += (size_t)res;
      } else if (res == 0 || res == -1) {
        LOG(LEVEL_INFO, "[ssl_transmit_hello]BIO_read: %d\n", res);
        break;
      } else {
        LOG(LEVEL_WARNING,
            "[ssl_transmit_hello]BIO_read failed with error: %d\n", res);
        LOGopenssl(LEVEL_WARNING);
        goto error1;
      }
    }
  } else {
    LOG(LEVEL_WARNING, "SSL_do_handshake failed with error: %d, ex_error: %d\n",
        res, res_ex);
    LOGopenssl(LEVEL_WARNING);
    goto error1;
  }

  pstate->sub.ssl_dynamic.handshake_state =
      SSL_get_state(pstate->sub.ssl_dynamic.ssl);
  tcp_transmit(more, pstate->sub.ssl_dynamic.data, offset, 0);
  return;
error1:
  switch_application_proto(banner1, pstate, resend_payload, banout, keyout,
                           PROTO_SSL3, &banner_ssl);
  application_receive_hello(banner1, pstate, resend_payload, banout, keyout,
                            more);
  return;
}

extern unsigned char ssl_test_case_1[];
extern size_t ssl_test_case_1_size;
extern unsigned char ssl_test_case_3[];
extern size_t ssl_test_case_3_size;
extern unsigned char google_cert[];
extern size_t google_cert_size;
extern unsigned char yahoo_cert[];
extern size_t yahoo_cert_size;

void print_all_for_test(struct BannerOutput *banout,
                        struct ProtocolState *state) {

  struct BannerOutput *iter_banout;

  int ssl_version;
  const SSL_CIPHER *ssl_cipher;
  uint16_t cipher_suite;
  STACK_OF(X509) * sk_x509_certs;
  int count_x509_certs;

  ssl_version = SSL_version(state->sub.ssl_dynamic.ssl);
  LOG(LEVEL_ERROR, "ssl_version 0x%X\n", ssl_version);

  cipher_suite = 0;
  ssl_cipher = SSL_get_current_cipher(state->sub.ssl_dynamic.ssl);
  if (ssl_cipher != NULL) {
    cipher_suite = SSL_CIPHER_get_protocol_id(ssl_cipher);
  }
  LOG(LEVEL_ERROR, "cipher suite 0x%X\n", cipher_suite);

  cipher_suite = 0;
  ssl_cipher = SSL_get_pending_cipher(state->sub.ssl_dynamic.ssl);
  if (ssl_cipher != NULL) {
    cipher_suite = SSL_CIPHER_get_protocol_id(ssl_cipher);
  }
  LOG(LEVEL_ERROR, "pending cipher suite 0x%X\n", cipher_suite);

  sk_x509_certs = SSL_get_peer_cert_chain(state->sub.ssl_dynamic.ssl);
  count_x509_certs = sk_X509_num(sk_x509_certs);
  LOG(LEVEL_ERROR, "count certs %d\n", count_x509_certs);

  LOG(LEVEL_ERROR, "handshake state %d\n",
      state->sub.ssl_dynamic.handshake_state);
  LOG(LEVEL_ERROR, "parse state %" PRIuPTR "\n", state->state);

  for (iter_banout = banout; iter_banout != NULL;
       iter_banout = iter_banout->next) {
    if (iter_banout->length && iter_banout->protocol) {
      LOG(LEVEL_ERROR, "banner: %" PRIu64 " %.*s\n",
          iter_banout->protocol & 0xFFFF, iter_banout->length,
          iter_banout->banner);
    }
  }
}

static int check_test_case_3(struct BannerOutput *banout,
                             struct ProtocolState *state) {
  int ssl_version;
  const SSL_CIPHER *ssl_cipher;
  uint16_t current_cipher_suite = 0;
  uint16_t pending_cipher_suite = 0;

  STACK_OF(X509) * sk_x509_certs;
  int count_x509_certs;
  bool res;

  if (state->parser_stream == &banner_http_over_ssl) {
    ssl_version = SSL_version(state->sub.ssl_dynamic.ssl);
    if (ssl_version != 0x301) {
      LOG(LEVEL_ERROR, "SSL Version failure\n");
      return 1;
    }

    ssl_cipher = SSL_get_current_cipher(state->sub.ssl_dynamic.ssl);
    if (ssl_cipher != NULL) {
      current_cipher_suite = SSL_CIPHER_get_protocol_id(ssl_cipher);
    }
    if (current_cipher_suite != 0 || ssl_cipher != NULL) {
      LOG(LEVEL_ERROR, "current cipher failure\n");
      return 1;
    }

    ssl_cipher = SSL_get_pending_cipher(state->sub.ssl_dynamic.ssl);
    if (ssl_cipher != NULL) {
      pending_cipher_suite = SSL_CIPHER_get_protocol_id(ssl_cipher);
    }
    if (pending_cipher_suite != 0x88 || ssl_cipher == NULL) {
      LOG(LEVEL_ERROR, "pending cipher failure\n");
      return 1;
    }

    sk_x509_certs = SSL_get_peer_cert_chain(state->sub.ssl_dynamic.ssl);
    count_x509_certs = sk_X509_num(sk_x509_certs);
    if (count_x509_certs != 2) {
      LOG(LEVEL_ERROR, "num cert failure\n");
      return 1;
    }

    if (state->sub.ssl_dynamic.handshake_state != TLS_ST_CR_KEY_EXCH) {
      LOG(LEVEL_ERROR, "handshake_state failure\n");
      return 1;
    }
    if (state->state != OPENSSL_UNKNOWN) {
      LOG(LEVEL_ERROR, "state failure\n");
      return 1;
    }
  }

  res = banout_is_contains(
      banout, PROTO_SSL3,
      "ubuntu.localdomain, puppet, puppet.localdomain, ubuntu.localdomain");
  if (!res) {
    LOG(LEVEL_ERROR, "banner names %.*s\n",
        (unsigned)banout_string_length(banout, PROTO_SSL3),
        banout_string(banout, PROTO_SSL3));
    return 1;
  }
  res = banout_is_contains(banout, PROTO_SSL3, "TLS/1.0 cipher:0x88");
  if (!res) {
    LOG(LEVEL_ERROR, "banner version or cipher failure\n");
    return 1;
  }
  res = banout_is_contains(banout, PROTO_SSL3, "ALERT(0x0233)");
  if (!res) {
    LOG(LEVEL_ERROR, "banner alert failure %.*s\n",
        (unsigned)banout_string_length(banout, PROTO_SSL3),
        banout_string(banout, PROTO_SSL3));
    return 1;
  }

  res = (banout_is_contains(banout, PROTO_X509_CERT,
                            "+LSkUHmlTtYNUgKalM5PQyA==") ||
         banout_is_contains(banout, PROTO_X509_CERT,
                            "txATssl6RwozPQOtSehtGDA=="));
  if (!res) {
    LOG(LEVEL_ERROR, "banner x509 failure\n");
    return 1;
  }

  return 0;
}

/*****************************************************************************
 *****************************************************************************/
static int ssl_selftest(void) {
  struct InteractiveData more = {0};
  struct Banner1 *banner1;
  struct BannerOutput banout1[1];
  struct SignOutput signout[1];
  struct KeyOutput *keyout = NULL;
  struct ProtocolState state[1];
  struct ResendPayload resend_payload;

  size_t i;

  /* Do the normal parse */
  banner1 = banner1_create();
  banner1->is_capture_cert = true;
  banner1_init(banner1);
  memset(state, 0, sizeof(state[0]));
  banout_init(banout1);
  signout_init(signout);
  keyout_init(&keyout);
  state->app_proto = PROTO_SSL3;
  state->parser_stream = &banner_http_over_ssl;
  init_application_proto(banner1, state, &resend_payload, banout1, &keyout);
  application_receive_hello(banner1, state, &resend_payload, banout1, &keyout,
                            &more);
  // FILE *fp = fopen("test.out.bin", "wb");
  // fwrite(more.m_payload, 1, more.m_length, fp);
  // fclose(fp);
  free_interactive_data(&more);
  application_receive_next(banner1, state, state, &resend_payload,
                           ssl_test_case_3, ssl_test_case_3_size, banout1,
                           signout, &keyout, &more);
  free_interactive_data(&more);
  if (check_test_case_3(banout1, state) != 0) {
    LOG(LEVEL_ERROR, "Failure test 0\n");
    return 1;
  }
  cleanup_application_proto(banner1, state, &resend_payload);
  keyout_release(&keyout);
  signout_release(signout);
  banner1_destroy(banner1);
  banout_release(banout1);

  /* Do the fragmented parse */
  banner1 = banner1_create();
  banner1->is_capture_cert = true;
  banner1_init(banner1);
  memset(state, 0, sizeof(state[0]));

  banout_init(banout1);
  signout_init(signout);
  keyout_init(&keyout);
  state->app_proto = PROTO_SSL3;
  state->parser_stream = &banner_http_over_ssl;
  init_application_proto(banner1, state, &resend_payload, banout1, &keyout);

  application_receive_hello(banner1, state, &resend_payload, banout1, &keyout,
                            &more);
  free_interactive_data(&more);

  for (i = 0; i < ssl_test_case_3_size; i++) {
    application_receive_next(banner1, state, state, &resend_payload,
                             ssl_test_case_3 + i, 1, banout1, signout, &keyout,
                             &more);
    free_interactive_data(&more);
  }
  if (check_test_case_3(banout1, state) != 0) {
    LOG(LEVEL_ERROR, "Failure test 1\n");
    return 1;
  }
  cleanup_application_proto(banner1, state, &resend_payload);
  keyout_release(&keyout);
  signout_release(signout);
  banner1_destroy(banner1);
  banout_release(banout1);

  return 0;
}

struct ProtocolParserStream *
get_ssl_parser_stream(const struct Banner1 *banner1) {
  if (banner1->is_ssl_dynamic && banner1->ssl_ctx) {
    return &banner_http_over_ssl;
  }
  return &banner_ssl;
}

/*****************************************************************************
 * This is the 'plugin' structure that registers callbacks for this parser in
 * the main system.
 *****************************************************************************/
struct ProtocolParserStream banner_http_over_ssl = {
    "ssl",
    PROTO_SSL3,
    false,
    NULL,
    0,
    0,
    ssl_selftest,
    ssl_init,
    ssl_cleanup,
    ssl_transmit_init,
    ssl_parse_record,
    ssl_transmit_cleanup,
    ssl_transmit_hello,
};
