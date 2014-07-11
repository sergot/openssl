module libbuf;

use LibraryMake;

our sub library {
    my $so = get-vars('')<SO>;
    for @*INC {
        if ($_~'/libbuf'~$so).IO ~~ :f {
            return $_~'/libbuf'~$so;
        }
    }
    die "Unable to find library";
}
