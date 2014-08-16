module OpenSSL::Err;

use NativeCall;

our sub ERR_error_string(Int $e) returns Str is native('libssl') {*};

our sub ERR_get_error() returns Int is native('libssl') {*};
