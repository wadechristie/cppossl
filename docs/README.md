# C++ utility library for OpenSSL
Trying to make life a little easier for interacting with OpenSSL in C++.

## Build
Requires cmake 3.18+
```
# mkdir _build && cd _build
# cmake ..
# cmake --build . -- -j$(nproc)
```

## Examples

### Loading a PEM
```cpp
#include <cppossl/pem.hpp>

ossl::owned<::X509> cert = ossl::pem::load<::X509>("-----BEGIN CERTIFICATE...");
ossl::owned<::X509_CRL> crl = ossl::pem::load<::X509_CRL>("----BEGIN X509 CRL...");
ossl::owned<::EVP_PKEY> key = ossl::pem::load<::EVP_PKEY>("-----BEGIN PRIVATE KEY...");
ossl::owned<::EVP_PKEY> enckey = ossl::pem::load<::EVP_PKEY>("-----BEGIN ENCRYPTED PRIVATE KEY...", "password");
```

### X.509 Self-Signed
```cpp
#include <cppossl/x509_builder.hpp>

ossl::owned<::EVP_PKEY> key = ossl::pem::load<::EVP_PKEY>("-----BEGIN PRIVATE KEY...");
ossl::owned<::X509> cert = ossl::x509::selfsign(key, EVP_sha256(),
    [](ossl::x509::builder& builder)
    {
        builder.set_subject(ossl::x509_name::parse("CN=Self-Signed"))
               .set_not_after(ossl::asn1_time::offset(std::chrono::hours(24) * 90))
               .set_key_usage_ext("digitalSignature, keyAgreement")
               .set_ext_key_usage_ext("serverAuth")
               .set_subject_alt_names_ext({
                    ossl::general_name::make_dns("example.com"),
                    ossl::general_name::make_ip("10.0.0.1"),
                });
    });
```

### X.509 Signing
```cpp
#include <cppossl/x509_builder.hpp>

ossl::owned<::X509> signing_cert = ossl::pem::load<::X509>("-----BEGIN CERTIFICATE...");
ossl::owned<::EVP_PKEY> signing_key = ossl::pem::load<::EVP_PKEY>("-----BEGIN PRIVATE KEY...");

ossl::owned<::EVP_PKEY> key = ossl::pem::load<::EVP_PKEY>("-----BEGIN PRIVATE KEY...");
ossl::owned<::X509> cert = ossl::x509::sign(signing_cert, signing_key, EVP_sha256(),
    [&key, &signing_cert](ossl::x509::builder& builder)
    {
        builder.set_subject(ossl::x509_name::parse("CN=Child Certificate"))
               .set_public_key(key)
               .set_not_after(ossl::asn1_time::offset(std::chrono::hours(24) * 90))
               .set_authority_key_id_ext(signing_cert)
               .set_key_usage_ext("digitalSignature, keyAgreement")
               .set_ext_key_usage_ext("serverAuth")
               .set_subject_alt_names_ext({
                    ossl::general_name::make_dns("example.com"),
                    ossl::general_name::make_ip("10.0.0.1"),
                });
    });
```
