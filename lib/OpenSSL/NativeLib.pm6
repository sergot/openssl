module OpenSSL::NativeLib;

sub ssl-lib is export {
    state $lib;
    unless $lib {
        if $*DISTRO.is-win {
            # try to find a bundled .dll
            $lib = find-bundled('ssleay32.dll');
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
            $lib = find-bundled('libeay32.dll');
        } else {
            $lib = 'libssl';
        }
    }
    $lib
}

sub find-bundled($lib is copy) {
    # if we can't find one, assume there's a system install
    for @*INC {
        if ($_ ~ '/OpenSSL/' ~ $lib).IO.f {
            $lib = $_ ~ '/OpenSSL/' ~ $lib;
            last;
        }
    }

    $lib;
}
