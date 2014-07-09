module OpenSSL::Session;

use NativeCall;

our class SSL_SESSION is repr('CStruct') {
    has int32 $.ssl_version;
}
