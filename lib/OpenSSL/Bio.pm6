unit module OpenSSL::Bio;

use OpenSSL::NativeLib;
use NativeCall;

class BIO_METHOD is repr('CStruct') {
    has int32 $.type;
    has Str $.name;
}

class CRYPTO_EX_DATA is repr('CStruct') {
    has OpaquePointer $.st;
    has int32 $.dummy;
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
    has long $.num_read;
    has long $.num_write;

    # inlined struct CRYPTO_EX_DATA
    has OpaquePointer $.st;
    has int32 $.dummy;
}

our sub BIO_new_bio_pair(CArray[OpaquePointer], long, CArray[OpaquePointer], long --> int32) is native(&gen-lib) { ... }
our sub BIO_free(OpaquePointer) is native(&gen-lib) { ... }
our sub BIO_read(OpaquePointer, Blob, long --> int32) is native(&gen-lib) { ... }
our sub BIO_write(OpaquePointer, Blob, long --> int32) is native(&gen-lib) { ... }
our sub BIO_new_mem_buf(Blob, long --> OpaquePointer) is native(&gen-lib) { ... }
