use OpenSSL;
use Test;

plan 1;

ok OpenSSL::SSLv23_client_method(), 'SSLv23_client_method';
