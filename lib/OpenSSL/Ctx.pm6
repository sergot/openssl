unit module OpenSSL::Ctx;

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
