unit module OpenSSL::Ctx;

use OpenSSL::Base;
use OpenSSL::NativeLib;
use OpenSSL::Method;
use NativeCall;

class SSL_CTX is repr('CStruct') {
    has OpenSSL::Method::SSL_METHOD $.method;
}

our sub SSL_CTX_new(OpenSSL::Method::SSL_METHOD) returns SSL_CTX is native(&ssl-lib) { ... }
our sub SSL_CTX_free(SSL_CTX) is native(&ssl-lib) { ... }

our sub SSL_CTX_use_certificate_file(SSL_CTX, Str, int32) returns int32 is native(&ssl-lib) { ... }
our sub SSL_CTX_use_PrivateKey_file(SSL_CTX, Str, int32) returns int32 is native(&ssl-lib) { ... }
our sub SSL_CTX_check_private_key(SSL_CTX) returns int32 is native(&ssl-lib) { ... }
our sub SSL_CTX_set_default_verify_paths(SSL_CTX) is native(&gen-lib) { ... }
our sub SSL_CTX_load_verify_locations(SSL_CTX, Str, Str) returns int32 is native(&gen-lib) { ... }
# ALPN
our sub SSL_CTX_set_alpn_protos(SSL_CTX, Buf, uint32) returns int32 is native(&gen-lib) { ... }
our sub SSL_CTX_set_alpn_select_cb(SSL_CTX, &callback (
                                   OpenSSL::Base::SSL,        # ssl
                                   CArray[CArray[uint8]],    # out
                                   CArray[uint8],            # outlen
                                   CArray[uint8],            # in
                                   uint8,                    # inlen
                                   Pointer --> int32),       # arg
                               Pointer)
    is native(&gen-lib) {*}
