module OpenSSL::X509;

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

our sub X509_get_pubkey(OpaquePointer --> OpaquePointer) is native($lib) { ... }
our sub X509_free(OpaquePointer) is native($lib) { ... }
