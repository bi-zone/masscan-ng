#ifndef UTIL_OPENSSL_H
#define UTIL_OPENSSL_H

#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>

#ifndef NID_id_on_SmtpUTF8Mailbox
#define SN_id_on_SmtpUTF8Mailbox "id-on-SmtpUTF8Mailbox"
#define LN_id_on_SmtpUTF8Mailbox "Smtp UTF8 Mailbox"
#endif
#define OID_id_on_SmtpUTF8Mailbox "1.3.6.1.5.5.7.8.9"

#ifndef NID_XmppAddr
#define SN_XmppAddr "id-on-xmppAddr"
#define LN_XmppAddr "XmppAddr"
#endif
#define OID_XmppAddr "1.3.6.1.5.5.7.8.5"

#ifndef NID_SRVName
#define SN_SRVName "id-on-dnsSRV"
#define LN_SRVName "SRVName"
#endif
#define OID_SRVName "1.3.6.1.5.5.7.8.7"

#ifndef NID_NAIRealm
#define SN_NAIRealm "id-on-NAIRealm"
#define LN_NAIRealm "NAIRealm"
#endif
#define OID_NAIRealm "1.3.6.1.5.5.7.8.8"

#ifndef NID_KRB5PrincipalName
#define SN_KRB5PrincipalName "id-on-pkinit-san"
#define LN_KRB5PrincipalName "KRB5PrincipalName"
#endif
#define OID_KRB5PrincipalName "1.3.6.1.5.2.2"

#ifndef NID_DomainController
#define SN_DomainController "id-ms-domain-controller"
#define LN_DomainController "Domain Controller"
#endif
#define OID_DomainController "1.3.6.1.4.1.311.25.1"

#ifndef NID_CiscoDlswTConnOperTable
#define SN_CiscoDlswTConnOperTable "id-cisco-dlswt-conn-oper-table"
#define LN_CiscoDlswTConnOperTable "Cisco DlswTConnOperTabler"
#endif
#define OID_CiscoDlswTConnOperTable "1.3.6.1.4.1.9.21.2.3"

#ifndef NID_AttributeSyntaxVendor
#define SN_AttributeSyntaxVendor "id-AttributeSyntaxVendor"
#define LN_AttributeSyntaxVendor "Attribute Syntax Vendor"
#endif
#define OID_AttributeSyntaxVendor "2.5.5.5"

int GENERAL_NAME_simple_print(BIO *out, GENERAL_NAME *gen);
void init_openssl_ext_obj();
int util_openssl_selftest();

#endif // UTIL_OPENSSL_H
