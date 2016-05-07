unit module OpenSSL::NativeLib;

sub ssl-lib is export {
    state $lib = $*DISTRO.is-win
        ?? %?RESOURCES<ssleay32.dll>.absolute
        !! $*VM.platform-library-name('ssl'.IO).Str;
}

sub gen-lib is export {
    state $lib = $*DISTRO.is-win
        ?? %?RESOURCES<libeay32.dll>.absolute
        !! $*VM.platform-library-name('ssl'.IO).Str;
}
