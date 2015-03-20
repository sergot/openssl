use Panda::Builder;

use Shell::Command;
use NativeCall;

# test sub for system library
our sub SSL_library_init() is native("ssleay32.dll") { ... }

class Build is Panda::Builder {
    method build($workdir) {
        my $need-copy = False;

        # we only have .dll files bundled. Non-windows is assumed to have openssl already
        if $*DISTRO.is-win {
            SSL_library_init();
            CATCH {
                default {
                    $need-copy = True;
                }
            }
        }

        if $need-copy {
            say 'No system OpenSSL library detected. Installing bundled version.';
            mkdir($workdir ~ '\blib\lib\OpenSSL');
            cp($workdir ~ '\native-lib\ssleay32.dll', $workdir ~ '\blib\lib\OpenSSL\ssleay32.dll');
            cp($workdir ~ '\native-lib\libeay32.dll', $workdir ~ '\blib\lib\OpenSSL\libeay32.dll');
        }
        else {
            say 'Found system OpenSSL library.';
        }
    }
}
