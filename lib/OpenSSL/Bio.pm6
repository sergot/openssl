module OpenSSL::Bio;

use NativeCall;

class BIO_METHOD is repr('CStruct') {
    has int32 $.type;
    has Str $.name;
}

class BIO is repr('CStruct') {
    has BIO_METHOD $.method;
    # some functions ?
    has Str $.cb_arg;

    has int32 $.init;
    has int32 $.shutdown;
    has int32 $.flags;
    has int32 $.retry_reason;
    has int32 $.num;
    has OpaquePointer $.ptr;

    has BIO $.next_bio;
    has BIO $.prev_bio;

    has int32 $.references;
    has int $.num_read;
    has int $.num_write;

    # ex_data ?
}
