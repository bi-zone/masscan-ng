#ifndef UTIL_OPENSSL_H
#define UTIL_OPENSSL_H

#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>

#ifndef NID_id_on_SmtpUTF8Mailbox
#define SN_id_on_SmtpUTF8Mailbox "id-on-SmtpUTF8Mailbox"
#define LN_id_on_SmtpUTF8Mailbox "Smtp UTF8 Mailbox"
#define OID_id_on_SmtpUTF8Mailbox "1.3.6.1.5.5.7.8.9"
#endif

#ifndef NID_XmppAddr
#define SN_XmppAddr "id-on-xmppAddr"
#define LN_XmppAddr "XmppAddr"
#define OID_XmppAddr "1.3.6.1.5.5.7.8.5"
#endif

#ifndef NID_SRVName
#define SN_SRVName "id-on-dnsSRV"
#define LN_SRVName "SRVName"
#define OID_SRVName "1.3.6.1.5.5.7.8.7"
#endif

#ifndef NID_NAIRealm
#define SN_NAIRealm "id-on-NAIRealm"
#define LN_NAIRealm "NAIRealm"
#define OID_NAIRealm "1.3.6.1.5.5.7.8.8"
#endif

#ifndef NID_KRB5PrincipalName
#define SN_KRB5PrincipalName "id-on-pkinit-san"
#define LN_KRB5PrincipalName "KRB5PrincipalName"
#define OID_KRB5PrincipalName "1.3.6.1.5.2.2"
#endif

#ifndef NID_DomainController
#define SN_DomainController "id-ms-domain-controller"
#define LN_DomainController "Domain Controller"
#define OID_DomainController "1.3.6.1.4.1.311.25.1"
#endif

#ifndef NID_CiscoDlswTConnOperTable
#define SN_CiscoDlswTConnOperTable "id-cisco-dlswt-conn-oper-table"
#define LN_CiscoDlswTConnOperTable "Cisco DlswTConnOperTabler"
#define OID_CiscoDlswTConnOperTable "1.3.6.1.4.1.9.21.2.3"
#endif

#ifndef NID_AttributeSyntaxVendor
#define SN_AttributeSyntaxVendor "id-AttributeSyntaxVendor"
#define LN_AttributeSyntaxVendor "Attribute Syntax Vendor"
#define OID_AttributeSyntaxVendor "2.5.5.5"
#endif

int GENERAL_NAME_simple_print(BIO *out, GENERAL_NAME *gen);
void init_openssl_ext_obj();
int util_openssl_selftest();

#endif // UTIL_OPENSSL_H
