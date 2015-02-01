module OpenSSL::Ctx;

my Str $lib;
BEGIN {
    if $*VM.config<dll> ~~ /dll/ {
        # we're on windows, different library name
        $lib = 'ssleay32.dll';
    } else {
        $lib = 'libssl';
    }
}

use OpenSSL::Method;
use NativeCall;

class SSL_CTX is repr('CStruct') {
    has OpenSSL::Method::SSL_METHOD $.method;
}

our sub SSL_CTX_new(OpenSSL::Method::SSL_METHOD) returns SSL_CTX is native($lib) { ... }
our sub SSL_CTX_free(SSL_CTX) is native($lib) { ... }

our sub SSL_CTX_use_certificate_file(SSL_CTX, Str, int32) returns int32 is native($lib) { ... }
our sub SSL_CTX_use_PrivateKey_file(SSL_CTX, Str, int32) returns int32 is native($lib) { ... }
our sub SSL_CTX_check_private_key(SSL_CTX) returns int32 is native($lib) { ... }
