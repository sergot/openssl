unit module OpenSSL::Base;

use OpenSSL::NativeLib;
use OpenSSL::Bio;
use OpenSSL::Method;

use NativeCall;

class SSL is repr('CStruct') {
    has int32 $.version;
    has int32 $.type;

    has OpenSSL::Method::SSL_METHOD $.method;

    has OpenSSL::Bio::BIO $.rbio;
    has OpenSSL::Bio::BIO $.wbio;
    has OpenSSL::Bio::BIO $.bbio;

    has int32 $.rwstate;

    has int32 $.in_handshake;

    # function
    has OpaquePointer $.handshake_func;

    has int32 $.server;

    has int32 $.new_session;

    has int32 $.quiet_shutdown;
    has int32 $.shutdown;

    has int32 $.state;
    has int32 $.rstate;
}
