unit module OpenSSL::NativeLib;

use NativeCall;

my $version;

sub ssl-lib is export {
    state @lib = $*DISTRO.is-win
        ?? dll-resource('ssleay32.dll')
        !! ('ssl', version)
}

sub gen-lib-unversioned() {
    $*DISTRO.is-win
        ?? dll-resource('libeay32.dll')
        !! 'ssl'
}

sub gen-lib-version($v) {
    @ = $*DISTRO.is-win
        ?? dll-resource('libeay32.dll')
        !! ('ssl', $v)
}

sub gen-lib() is export {
    state @lib = $*DISTRO.is-win
        ?? dll-resource('libeay32.dll')
        !! ('ssl', version)
}

sub crypto-lib is export {
    state @lib = $*DISTRO.is-win
        ?? dll-resource('libeay32.dll')
        !! ('crypto', version)
}

sub version() {
    unless defined $version {
        for (v1.1, v1.0, v1.0.0) -> $v {
            try {
                my sub EVP_aes_128_cbc( --> Pointer) { };
                trait_mod:<is>(&EVP_aes_128_cbc, :native(gen-lib-version($v)));
                EVP_aes_128_cbc();
                $version = $v;
            }
            last if $version;
        }

        try {
            my sub EVP_aes_128_cbc( --> Pointer) { };
            trait_mod:<is>(&EVP_aes_128_cbc, :native(gen-lib-unversioned()));
            EVP_aes_128_cbc();
            $version = '';
        }

        die "Did not find {$*VM.platform-library-name('ssl'.IO)}" unless defined $version;
    }
    $version
}

# Windows only
# Problem: The dll files in resources/ don't like to be renamed, but CompUnit::Repository::Installation
# does not provide a mechanism for storing resources without name mangling. Find::Bundled provided
# this before, but it has suffered significant bit rot.
# "Fix": Continue to store the name mangled resource. Check $*TMPDIR/<sha1 of resource path>/$basename
# and use it if it exists, otherwise copy the name mangled file to this location but using the
# original unmangled name.
# XXX: This should be removed when CURI/%?RESOURCES gets a mechanism to bypass name mangling
use nqp;
sub dll-resource($resource-name) {
    my $resource      = %?RESOURCES{$resource-name};
    return $resource.absolute if $resource.basename eq $resource-name;

    my $content_id    = nqp::sha1($resource.absolute);
    my $content_store = $*TMPDIR.child($content_id);
    my $content_file  = $content_store.child($resource-name).absolute;
    return $content_file if $content_file.IO.e;

    mkdir $content_store unless $content_store.e;
    copy($resource, $content_file);

    $content_file;
}
