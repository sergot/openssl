unit module OpenSSL::X509_Store_Ctx;

use v6;
use NativeCall;
use OpenSSL::NativeLib;


# struct crypto_ex_data_st {
#     STACK_OF(void) *sk;
# };
# class CRYPTO_EX_DATA is repr('CStruct') {
#    has Pointer $.sk;
#}


# class X509_STORE_CTX is repr('CStruct') {
#     # X509_STORE *ctx;
#     has OpaquePointer $.ctx;

#     # /* The following are set by the caller */
#     # /* The cert to check */
#     # X509 *cert;
#     has OpaquePointer $.cert;

#     # /* chain of X509s - untrusted - passed in */
#     # STACK_OF(X509) *untrusted;
#     has Pointer $.untrusted;

#     # /* set of CRLs passed in */
#     # STACK_OF(X509_CRL) *crls;
#     # X509_VERIFY_PARAM *param;
#     has Pointer $.crls;
#     has Pointer $.param;

#     # /* Other info for use with get_issuer() */
#     # void *other_ctx;
#     has Pointer $.other_ctx;

#     # /* Callbacks for various operations */
#     # /* called to verify a certificate */
#     # int (*verify) (X509_STORE_CTX *ctx)
#     has Pointer $.verify;

#     # /* error callback */
#     # int (*verify_cb) (int ok, X509_STORE_CTX *ctx);
#     has Pointer $.verify_cb;

#     # /* get issuers cert from ctx */
#     # int (*get_issuer) (X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
#     has Pointer $.get_issuer;

#     # /* check issued */
#     # int (*check_issued) (X509_STORE_CTX *ctx, X509 *x, X509 *issuer);
#     has Pointer $.check_issued;

#     # /* Check revocation status of chain */
#     # int (*check_revocation) (X509_STORE_CTX *ctx);
#     has Pointer $.check_revocation;

#     # /* retrieve CRL */
#     # int (*get_crl) (X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x);
#     has Pointer $.get_crl;

#     # /* Check CRL validity */
#     # int (*check_crl) (X509_STORE_CTX *ctx, X509_CRL *crl);
#     has Pointer $.check_crl;

#     # /* Check certificate against CRL */
#     # int (*cert_crl) (X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x);
#     has Pointer $.cert_crl;

#     # /* Check policy status of the chain */
#     # int (*check_policy) (X509_STORE_CTX *ctx);
#     has Pointer $.check_policy;

#     # STACK_OF(X509) *(*lookup_certs) (X509_STORE_CTX *ctx, X509_NAME *nm);
#     has Pointer $.lookup_certs;

#     # STACK_OF(X509_CRL) *(*lookup_crls) (X509_STORE_CTX *ctx, X509_NAME *nm);
#     has Pointer $.lookup_crls;

#     # int (*cleanup) (X509_STORE_CTX *ctx);
#     has Pointer $.cleanup;

#     # /* The following is built up */
#     # /* if 0, rebuild chain */
#     # int valid;
#     has int32 $.valid;

#     # /* number of untrusted certs */
#     # int num_untrusted;
#     has int32 $.num_untrusted;

#     # /* chain of X509s - built up and trusted */
#     # STACK_OF(X509) *chain;
#     has Pointer $.chain;

#     # /* Valid policy tree */
#     # X509_POLICY_TREE *tree;
#     has Pointer $.tree;

#     # /* Require explicit policy value */
#     # int explicit_policy;
#     has int32 $explicit_policy;

#     # /* When something goes wrong, this is why */
#     # int error_depth;
#     has int32 $.error_depth;

#     # int error;
#     has int32 $.error;

#     # X509 *current_cert;
#     has Pointer $.current_cert;

#     # /* cert currently being tested as valid issuer */
#     # X509 *current_issuer;
#     has Pointer $.current_issuer;

#     # /* current CRL */
#     # X509_CRL *current_crl;
#     has Pointer $.current_crl;

#     # /* score of current CRL */
#     # int current_crl_score;
#     has int32 $.current_crl_score;

#     # /* Reason mask */
#     # unsigned int current_reasons;
#     has uint32 $.current_reasons;

#     # /* For CRL path validation: parent context */
#     # X509_STORE_CTX *parent;
#     has OpenSSL::Ctx::X509_STORE_CTX $.parent;
#     # CRYPTO_EX_DATA ex_data;
#     HAS CRYPTO_EX_DATA $.ex_data;

#     # SSL_DANE *dane;
#     has Pointer $.dane;

#     # /* signed via bare TA public key, rather than CA certificate */
#     # int bare_ta_signed;
#     has int32 $.bare_ta_signed;
# }

our sub X509_STORE_CTX_get_current_cert(Pointer) returns Pointer is native(&ssl-lib) { ... }
our sub X509_STORE_CTX_get_error_depth(Pointer) returns int32 is native(&ssl-lib) { ... }
