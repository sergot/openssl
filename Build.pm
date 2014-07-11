use v6;
use Panda::Common;
use Panda::Builder;
use Shell::Command;
use LibraryMake;

class Build is Panda::Builder {
    method build($dir) {
        shell "mkdir -p $dir/blib/lib";
        make "$dir/src", "$dir/blib/lib";
    }
}
