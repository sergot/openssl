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
    my $base = "lib/OpenSSL/$lib";
    for @*INC {
        if my @files = ($_.files($base) || $_.files("blib/$base")) {
            my $files = @files[0]<files>;
            my $tmp = $files{$base} || $files{"blib/$base"};

            # copy to a temp dir
            $tmp.IO.copy($*SPEC.tmpdir ~ '\\' ~ $lib);
            $lib = $*SPEC.tmpdir ~ '\\' ~ $lib;

            last;
        }
    }

    $lib;
}
