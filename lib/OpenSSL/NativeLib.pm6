unit module OpenSSL::NativeLib;
use Find::Bundled;

sub ssl-lib is export {
    state $lib;
    unless $lib {
        if $*DISTRO.is-win {
            # try to find a bundled .dll
            $lib = Find::Bundled.find('ssleay32.dll', 'OpenSSL', :return-original, :keep-filename);
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
            $lib = Find::Bundled.find('libeay32.dll', 'OpenSSL', :return-original, :keep-filename);
        } else {
            $lib = 'libssl';
        }
    }
    $lib
}
