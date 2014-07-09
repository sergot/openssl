class OpenSSL;

use OpenSSL::SSL;

has $.ctx;
has $.ssl;
has $.client;

method new(:$version? is copy) {
    OpenSSL::SSL::SSL_library_init();

    my $method;
    if $version.defined {
        $method = $version == 2 ?? OpenSSL::Method::SSLv2_client_method() !! OpenSSL::Method::SSLv3_client_method();
    }
    else {
        $method = OpenSSL::Method::SSLv23_client_method();
    }
    my $ctx     = OpenSSL::Ctx::SSL_CTX_new( $method );
    my $ssl     = OpenSSL::SSL::SSL_new( $ctx );

    self.bless(:$ctx, :$ssl);
}
