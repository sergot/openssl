module OpenSSL::PEM;

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

our sub PEM_read_bio_RSAPrivateKey(OpaquePointer, OpaquePointer, OpaquePointer, OpaquePointer --> OpaquePointer) is native($lib) { ... }
our sub PEM_read_bio_RSAPublicKey(OpaquePointer, OpaquePointer, OpaquePointer, OpaquePointer --> OpaquePointer) is native($lib) { ... }
our sub PEM_read_bio_X509(OpaquePointer, OpaquePointer, OpaquePointer, OpaquePointer --> OpaquePointer) is native($lib) { ... }
