unit module OpenSSL::X509;

use OpenSSL::NativeLib;
use NativeCall;

our sub X509_get_pubkey(OpaquePointer --> OpaquePointer) is native(&gen-lib) { ... }
our sub X509_free(OpaquePointer) is native(&gen-lib) { ... }
