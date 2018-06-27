#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

static STACK_OF(X509)* SK_X509_push(X509 *cert) {
    STACK_OF(X509) *ca = sk_X509_new_null();
    sk_X509_push(ca, cert);
    return ca;
}

static void SK_X509_Free(STACK_OF(X509) *ca) {
    sk_X509_free(ca);
}

static void OPENSSL_load() {
    OpenSSL_add_all_algorithms();
}
