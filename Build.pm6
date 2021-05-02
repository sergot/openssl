unit class Build;

method build($cwd --> Bool) {
    my %libraries = ssl => 'ssl', crypto => 'crypto';

    my $prefix;
    if %*ENV<OPENSSL_PREFIX>:exists {
        $prefix = %*ENV<OPENSSL_PREFIX>;
    } elsif !$*DISTRO.is-win {
        my $proc = run "brew", "--prefix", "openssl", :out, :!err;
        if ?$proc {
            $prefix = $proc.out.slurp(:close).chomp;
        }
    }
    if $prefix {
        note "Using openssl prefix $prefix";
        %libraries =
            ssl    => $prefix.IO.child('lib').child('ssl').Str,
            crypto => $prefix.IO.child('lib').child('crypto').Str,
        ;
    }

    my $json = Rakudo::Internals::JSON.to-json: %libraries, :pretty, :sorted-keys;
    "resources/libraries.json".IO.spurt: $json;
    return True;
}
