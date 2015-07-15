require 'openssl'

p = OpenSSL::BN::generate_prime(3072)
puts p