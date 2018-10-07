openssl ecparam -out private.key -name prime256v1 -genkey
openssl req   -config openssl.cnf \
              -new \
              -x509 \
              -key private.key \
              -sha256 \
              -days 1 \
              -subj "/C=JP/ST=Tokyo/O=Beyond-Blockchain/CN=bbc1" \
              -extensions v3_ca \
              -out self-signed.pem
