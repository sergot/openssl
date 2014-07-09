module OpenSSL::Ctx;

use OpenSSL::Method;
use NativeCall;

our class SSL_CTX is repr('CStruct') {
    has OpenSSL::Method::SSL_METHOD $.method;
}

our sub SSL_CTX_new(OpenSSL::Method::SSL_METHOD) returns SSL_CTX is native('libssl') { * }
our sub SSL_CTX_free(SSL_CTX) is native('libssl') { * }
