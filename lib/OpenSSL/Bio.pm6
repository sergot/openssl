unit module OpenSSL::Bio;

use OpenSSL::NativeLib;
use NativeCall;

class BIO is repr('CPointer') {
}

our sub BIO_new_bio_pair(CArray[OpaquePointer], long, CArray[OpaquePointer], long --> int32) is native(&gen-lib) { ... }
our sub BIO_free(OpaquePointer) is native(&gen-lib) { ... }
our sub BIO_read(OpaquePointer, Blob, long --> int32) is native(&gen-lib) { ... }
our sub BIO_write(OpaquePointer, Blob, long --> int32) is native(&gen-lib) { ... }
our sub BIO_new_mem_buf(Blob, long --> OpaquePointer) is native(&gen-lib) { ... }
