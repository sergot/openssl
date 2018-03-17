unit module OpenSSL::SSL;

use OpenSSL::NativeLib;
use OpenSSL::Bio;
use OpenSSL::Method;
use OpenSSL::Ctx;
use OpenSSL::Stack;
use OpenSSL::Base;

use NativeCall;

constant SSL_VERIFY_NONE                 = 0x00;
constant SSL_VERIFY_PEER                 = 0x01;
constant SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
constant SSL_VERIFY_CLIENT_ONCE          = 0x04;
constant SSL_VERIFY_POST_HANDSHAKE       = 0x08;


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
our sub SSL_set_verify(OpenSSL::Base::SSL, int32,
                       &callback ( int32,
                                   #OpenSSL::Ctx::X509_STORE_CTX
                                   Pointer
                                       --> int32)) is native(&ssl-lib) { ... }
