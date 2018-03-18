use OpenSSL;
use Test;

plan 4;

unless %*ENV<NETWORK_TESTING> {
    diag "NETWORK_TESTING was not set";
    skip-rest("NETWORK_TESTING was not set");
    exit;
}

check(fetch('google.com', '/'));

sub check($result) {
    if $result ~~ /200 \s+ OK/ {
        pass 'Got good response';
    }
    elsif $result ~~ /302 \s+ Found/ && $result ~~ /^^'Location:' \s* $<location>=[\N+]/ {
        diag 'Got a redirect, following...';
        subtest {
            check(fetch('google.com', $<location>));
        }, 'Got good response after redirection';
    }
    else {
        fail 'Got good response';
    }
}

sub verify-cb($preverify_ok, $x509_ctx) {
    say "preverify_ok: " ~ ($preverify_ok == 0 ?? 'failed' !! 'passed');
    my $peer-cert = OpenSSL::X509_Store_Ctx::X509_STORE_CTX_get_current_cert($x509_ctx);
    my $depth = OpenSSL::X509_Store_Ctx::X509_STORE_CTX_get_error_depth($x509_ctx);
    my $bp = OpenSSL::Bio::BIO_new(OpenSSL::Bio::BIO_s_mem());
    if $bp && $peer-cert {
        my $pathlen = OpenSSL::X509::X509_get_pathlen($peer-cert);
        say $pathlen;

        my $n = OpenSSL::Bio::BIO_ctrl_pending($bp);
        say $n;

        say OpenSSL::PEM::PEM_write_bio_X509($bp, $peer-cert);
        my $buf = buf8.new.reallocate($n);
        OpenSSL::BIO::BIO_read($bp, $buf, $n);
        say $buf.perl;
    }
    return $preverify_ok;
}

sub fetch($host, $url) {
    my $ssl = OpenSSL.new(:client);
    $ssl.set-verify(OpenSSL::SSL::SSL_VERIFY_PEER, &verify-cb);
    my $s = IO::Socket::INET.new(:$host, :port(443));
    is $ssl.set-socket($s), 0, 'set-socket success';
    $ssl.set-connect-state;
    is $ssl.connect, 1, 'connect success';
    is $ssl.write("GET $url HTTP/1.1\r\nHost:www.$host\r\nConnection:close\r\n\r\n"), 46 + $url.chars + $host.chars, 'write success';

    #slurp it all up
    my $result = '';
    loop {
        my $tmp = $ssl.read(1024);
        if $tmp.chars {
            $result ~= $tmp;
        } else {
            last;
        }
    }

    $ssl.close;
    $s.close;
    $result
}

