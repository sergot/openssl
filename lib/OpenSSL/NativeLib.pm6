module OpenSSL::NativeLib;

sub ssl-lib is export {
    state $lib;
    unless $lib {
        if $*DISTRO.is-win {
            $lib = 'ssleay32.dll';
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
            $lib = 'libeay32.dll';
        } else {
            $lib = 'libssl';
        }
    }
    $lib
}
