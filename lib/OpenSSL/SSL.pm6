unit module OpenSSL::SSL;

use OpenSSL::NativeLib;
use OpenSSL::Bio;
use OpenSSL::Method;
use OpenSSL::Ctx;
use OpenSSL::Stack;
use OpenSSL::Base;

use NativeCall;

our sub SSL_library_init() is native(&ssl-lib)                                 { ... }
our sub OPENSSL_init_ssl(uint64, OpaquePointer) is native(&ssl-lib)            { ... }
our sub SSL_load_error_strings() is native(&ssl-lib)                           { ... }

our sub SSL_new(OpenSSL::Ctx::SSL_CTX) returns OpenSSL::Base::SSL is native(&ssl-lib)         { ... }
our sub SSL_set_fd(OpenSSL::Base::SSL, int32) returns int32 is native(&ssl-lib)               { ... }
our sub SSL_shutdown(OpenSSL::Base::SSL) returns int32 is native(&ssl-lib)                    { ... }
our sub SSL_free(OpenSSL::Base::SSL) is native(&ssl-lib)                                      { ... }
our sub SSL_get_error(OpenSSL::Base::SSL, int32) returns int32 is native(&ssl-lib)            { ... }
our sub SSL_accept(OpenSSL::Base::SSL) returns int32 is native(&ssl-lib)                      { ... }
our sub SSL_connect(OpenSSL::Base::SSL) returns int32 is native(&ssl-lib)                     { ... }
our sub SSL_read(OpenSSL::Base::SSL, Blob, int32) returns int32 is native(&ssl-lib)  { ... }
our sub SSL_write(OpenSSL::Base::SSL, Blob, int32) returns int32 is native(&ssl-lib) { ... }
our sub SSL_set_connect_state(OpenSSL::Base::SSL) is native(&ssl-lib)                         { ... }
our sub SSL_set_accept_state(OpenSSL::Base::SSL) is native(&ssl-lib)                          { ... }

our sub SSL_set_bio(OpenSSL::Base::SSL, OpaquePointer, OpaquePointer) returns int32 is native(&ssl-lib) { ... }

our sub SSL_load_client_CA_file(CArray[uint8]) returns OpenSSL::Stack is native(&ssl-lib)  { ... };
our sub SSL_get_client_CA_list(OpenSSL::Base::SSL) returns OpenSSL::Stack is native(&ssl-lib)             { ... };
our sub SSL_set_client_CA_list(OpenSSL::Base::SSL, OpenSSL::Stack) is native(&ssl-lib)                    { ... };

our sub SSL_do_handshake(OpenSSL::Base::SSL) returns int32 is native(&gen-lib) { ... }
our sub SSL_get_verify_result(OpenSSL::Base::SSL) returns int32 is native(&gen-lib) { ... }
our sub SSL_get_peer_certificate(OpenSSL::Base::SSL) returns Pointer is native(&gen-lib) { ... }
our sub SSL_get0_alpn_selected(OpenSSL::Base::SSL, CArray[CArray[uint8]], uint32 is rw) is native(&gen-lib) { ... }

# long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)
our sub SSL_ctrl(OpenSSL::Base::SSL, int32, int64, Str ) returns int64 is native(&ssl-lib) { ... }
