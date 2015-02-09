module OpenSSL::Err;

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

our sub ERR_error_string(Int $e, Str $ret = Str) returns Str is native($lib) { ... };

our sub ERR_get_error() returns Int is native($lib) { ... };
