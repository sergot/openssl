unit module OpenSSL::NativeLib;
use LibraryMake;

sub ssl-lib is export {
    state $lib;
    unless $lib {
        if $*DISTRO.is-win {
            # try to find a bundled .dll
            $lib = find-bundled('ssleay32.dll', 'OpenSSL');
        } else {
            $lib = 'libssl';
        }
    }
    $lib
}

sub gen-lib is export {
    state $lib;
    unless $lib {
        if $*DISTRO.is-win {
            # try to find a bundled .dll
            $lib = find-bundled('libeay32.dll', 'OpenSSL');
        } else {
            $lib = 'libssl';
        }
    }
    $lib
}
