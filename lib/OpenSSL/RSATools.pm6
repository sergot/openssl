use OpenSSL::RSA;
use OpenSSL::Bio;
use OpenSSL::PEM;
use OpenSSL::X509;
use OpenSSL::EVP;
use OpenSSL::Digest;

use NativeCall;

class OpenSSL::RSAKey {
    has $.private;
    has $.rsa;

    submethod DESTROY {
        OpenSSL::RSA::RSA_free($!rsa);
    }

    method new(:$private-pem, :$public-pem, :$x509-pem) {
        if $private-pem {
            my $bio-buf = OpenSSL::Bio::BIO_new_mem_buf($private-pem.encode, $private-pem.encode.bytes);
            my $rsa = OpenSSL::PEM::PEM_read_bio_RSAPrivateKey($bio-buf, OpaquePointer, OpaquePointer, OpaquePointer);
            OpenSSL::Bio::BIO_free($bio-buf);
            die "Unable to read key" unless defined($rsa);

            return self.bless(:$rsa, :private(True));
        }
        elsif $public-pem {
            my $bio-buf = OpenSSL::Bio::BIO_new_mem_buf($public-pem.encode, $public-pem.encode.bytes);
            my $rsa;
            if $public-pem ~~ /RSA/ {
                $rsa = OpenSSL::PEM::PEM_read_bio_RSAPublicKey($bio-buf, OpaquePointer, OpaquePointer, OpaquePointer);
            }
            else {
                $rsa = OpenSSL::PEM::PEM_read_bio_RSA_PUBKEY($bio-buf, OpaquePointer, OpaquePointer, OpaquePointer);
            }
            OpenSSL::Bio::BIO_free($bio-buf);
            die "Unable to read key" unless defined($rsa);

            return self.bless(:$rsa, :private(False));
        }
        elsif $x509-pem {
            my $bio-buf = OpenSSL::Bio::BIO_new_mem_buf($x509-pem.encode, $x509-pem.encode.bytes);

            my $x509 = OpenSSL::PEM::PEM_read_bio_X509($bio-buf, OpaquePointer, OpaquePointer, OpaquePointer);
            OpenSSL::Bio::BIO_free($bio-buf);
            die "Unable to read key" unless defined($x509);

            my $evp-key = OpenSSL::X509::X509_get_pubkey($x509);
            OpenSSL::X509::X509_free($x509);
            die "Unable to read key" unless defined($evp-key);

            my $rsa = OpenSSL::EVP::EVP_PKEY_get1_RSA($evp-key);
            OpenSSL::EVP::EVP_PKEY_free($evp-key);
            die "Unable to read key" unless defined($rsa);

            return self.bless(:$rsa, :private(False));
        }
        else {
            die "Please pass one of private-pem, public-pem, x509-pem.\nNo other formats are currently supported.";
        }
    }

    method sign(Blob $blob, :$sha1, :$sha256) {
        die "Must have private key to sign" unless $.private;
        my $hashed;
        my $type;
        if $sha256 {
            $hashed = sha256($blob);
            $type   = 672; # NID_sha256
        }
        else {
            $hashed = sha1($blob);
            $type   = 64; # NID_sha1
        }

        my $sig = buf8.new;
        my $slen = CArray[int32].new;
        $slen[0] = OpenSSL::RSA::RSA_size($.rsa);
        $sig[$slen[0]-1] = 0;
        my $ret = OpenSSL::RSA::RSA_sign($type, $hashed, $hashed.bytes, $sig, $slen, $.rsa);

        die "Failed to sign" unless $ret == 1;

        return $sig.subbuf(0, $slen[0]);
    }

    method verify(Blob $blob, Blob $sig, :$sha1, :$sha256) {
        my $hashed;
        my $type;
        if $sha256 {
            $hashed = sha256($blob);
            $type   = 672; # NID_sha256
        }
        else {
            $hashed = sha1($blob);
            $type   = 64; # NID_sha1
        }

        my $ret = OpenSSL::RSA::RSA_verify($type, $hashed, $hashed.bytes, $sig, $sig.bytes, $.rsa);

        return True if $ret == 1;
        return False;
    }
}
