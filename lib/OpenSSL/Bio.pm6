module OpenSSL::Bio;

my Str $lib;
BEGIN {
    if $*VM.config<dll> ~~ /dll/ {
        # we're on windows, different library name
        $lib = 'libeay32.dll';
    } else {
        $lib = 'libssl';
    }
}

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

our sub BIO_new_bio_pair(CArray[OpaquePointer], int, CArray[OpaquePointer], int --> int32) is native($lib) { ... }
our sub BIO_free(OpaquePointer) is native($lib) { ... }
our sub BIO_read(OpaquePointer, Blob, int --> int32) is native($lib) { ... }
our sub BIO_write(OpaquePointer, Blob, int --> int32) is native($lib) { ... }