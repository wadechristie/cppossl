//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/x509_builder.hpp>
#include <cppossl/x509_req_builder.hpp>

#include "common.hpp"

using namespace ossl;

using Catch::Matchers::ContainsSubstring;

struct x509_builder_test
{
    owned<::X509_NAME> name(std::string_view const& common_name)
    {
        return x509_name::build([&common_name](owned<::X509_NAME>& name) {
            x509_name::set_organization_name(name,
                {
                    "X.509 Builder",
                });
            x509_name::set_common_name(name, common_name);
        });
    }
};

TEST_CASE_METHOD(x509_builder_test, "X.509 Builder - Selfsign", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();
    auto const subject = name("Self-Signed");
    auto cert = x509::selfsign(
        key, unittest::default_digest(), [&subject](x509::builder& builder) { builder.set_subject(subject); });
    REQUIRE(cert);
    REQUIRE(x509_name::equal(subject, x509::get_subject(cert)));
    REQUIRE(x509_name::equal(subject, x509::get_issuer(cert)));
    // Default notBefore/notAfter is now
    REQUIRE(x509::get_not_before(cert) == x509::get_not_after(cert));
    REQUIRE(x509::check_key(cert, key));
}

TEST_CASE_METHOD(x509_builder_test, "X.509 Builder - Sign", "[x509][builder]")
{
    auto const signing_key = unittest::rsa_key_one.load();
    auto const child_key = unittest::rsa_key_two.load();

    auto signing_cert = x509::selfsign(signing_key, unittest::default_digest(), [this](x509::builder& builder) {
        builder.set_subject(name("Signing Cert"));
    });
    REQUIRE(signing_cert);

    auto child_cert
        = x509::sign(signing_cert, signing_key, unittest::default_digest(), [this, &child_key](x509::builder& builder) {
              builder.set_subject(name("Child Cert")).set_public_key(child_key);
          });
    REQUIRE(child_cert);
    REQUIRE(x509_name::equal(x509::get_subject(signing_cert), x509::get_issuer(child_cert)));
    REQUIRE(x509::check_key(child_cert, child_key));
}

TEST_CASE_METHOD(x509_builder_test, "X.509 Builder - notBefore/notAfter", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();
    time_t const now = time(nullptr);
    time_t const lastweek = now - (std::chrono::hours(24) * 7).count();
    time_t const nextweek = now + (std::chrono::hours(24) * 7).count();

    auto cert = x509::selfsign(key, unittest::default_digest(), [this, lastweek, nextweek](x509::builder& builder) {
        builder.set_subject(name("notBefore/notAfter"))
            .set_not_before(asn1::time::from_unix(lastweek))
            .set_not_after(asn1::time::from_unix(nextweek));
    });
    REQUIRE(cert);
    REQUIRE(x509::get_not_before(cert) == lastweek);
    REQUIRE(x509::get_not_after(cert) == nextweek);
}

TEST_CASE_METHOD(x509_builder_test, "X.509 Builder - Basic Constraints", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();

    SECTION("Basic Constraints - CA:TRUE")
    {
        auto cert = x509::selfsign(key, unittest::default_digest(), [this](x509::builder& builder) {
            builder.set_subject(name("Basic Constraints")).set_basic_constraints_ext(/*ca=*/true);
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Basic Constraints: critical\n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("CA:TRUE\n"));
    }

    SECTION("Basic Constraints - CA:TRUE, pathlen=1")
    {
        auto cert = x509::selfsign(key, unittest::default_digest(), [this](x509::builder& builder) {
            builder.set_subject(name("Basic Constraints")).set_basic_constraints_ext(/*ca=*/true, /*pathlen=*/1);
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Basic Constraints: critical\n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("CA:TRUE, pathlen:1\n"));
    }

    SECTION("Basic Constraints - CA:FALSE")
    {
        auto cert = x509::selfsign(key, unittest::default_digest(), [this](x509::builder& builder) {
            builder.set_subject(name("Basic Constraints")).set_basic_constraints_ext(/*ca=*/false);
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Basic Constraints: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("CA:FALSE\n"));
    }
}

TEST_CASE_METHOD(x509_builder_test, "X.509 Builder - Key Usage", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();

    SECTION("Critical")
    {
        auto cert = x509::selfsign(key, unittest::default_digest(), [this](x509::builder& builder) {
            builder.set_subject(name("Key Usage"))
                .set_key_usage_ext("digitalSignature, keyAgreement", /*critical=*/true);
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Key Usage: critical\n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("Digital Signature, Key Agreement\n"));
    }

    SECTION("Non-Critical")
    {
        auto cert = x509::selfsign(key, unittest::default_digest(), [this](x509::builder& builder) {
            builder.set_subject(name("Key Usage")).set_key_usage_ext("keyEncipherment, dataEncipherment");
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Key Usage: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("Key Encipherment, Data Encipherment\n"));
    }

    SECTION("Invalid Usage String")
    {
        REQUIRE_THROWS_AS(x509::selfsign(key,
                              EVP_sha256(),
                              [this](x509::builder& builder) {
                                  builder.set_subject(name("Key Usage"))
                                      .set_key_usage_ext("keyEncipherment, dataEncipherment, invalidUsage");
                              }),
            openssl_error);
    }
}

TEST_CASE_METHOD(x509_builder_test, "X.509 Builder - Extended Key Usage Identifier", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();

    SECTION("Critical")
    {
        auto cert = x509::selfsign(key, unittest::default_digest(), [this](x509::builder& builder) {
            builder.set_subject(name("Extended Key Usage")).set_ext_key_usage_ext("serverAuth", /*critical=*/true);
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Extended Key Usage: critical\n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("TLS Web Server Authentication\n"));
    }

    SECTION("Non-Critical")
    {
        auto cert = x509::selfsign(key, unittest::default_digest(), [this](x509::builder& builder) {
            builder.set_subject(name("Extended Key Usage")).set_ext_key_usage_ext("codeSigning, timeStamping");
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Extended Key Usage: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("Code Signing, Time Stamping\n"));
    }

    SECTION("Invalid Usage String")
    {
        REQUIRE_THROWS_AS(
            x509::selfsign(key,
                EVP_sha256(),
                [this](x509::builder& builder) {
                    builder.set_subject(name("Extended Key Usage")).set_ext_key_usage_ext("serverAuth, invalidUsage");
                }),
            openssl_error);
    }
}

TEST_CASE_METHOD(x509_builder_test, "X.509 Builder - Subject Key Identifier", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();

    SECTION("Subject Key Identifier")
    {
        auto cert = x509::selfsign(key, unittest::default_digest(), [this, &key](x509::builder& builder) {
            builder.set_subject(name("Subject Key Identifier")).set_public_key(key).set_subject_key_id_ext();
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("509v3 Subject Key Identifier: \n"));
    }

    SECTION("Public Key Not Set")
    {
        REQUIRE_THROWS_AS((void)x509::selfsign(key,
                              EVP_sha256(),
                              [this](x509::builder& builder) {
                                  builder.set_subject(name("Subject Key Identifier")).set_subject_key_id_ext();
                              }),
            std::system_error);
    }
}

TEST_CASE_METHOD(x509_builder_test, "X.509 Builder - Authority Key Identifier", "[x509][builder]")
{
    auto const signing_key = unittest::rsa_key_one.load();
    auto const child_key = unittest::rsa_key_two.load();

    auto signing_cert
        = x509::selfsign(signing_key, unittest::default_digest(), [this, &signing_key](x509::builder& builder) {
              builder.set_subject(name("Signing Cert"))
                  .set_public_key(signing_key)
                  .set_basic_constraints_ext(/*ca=*/true, /*pathlen=*/0)
                  .set_subject_key_id_ext();
          });
    REQUIRE(signing_cert);

    auto child_cert = x509::sign(signing_cert,
        signing_key,
        unittest::default_digest(),
        [this, &signing_cert, &child_key](x509::builder& builder) {
            builder.set_subject(name("Child Cert")).set_public_key(child_key).set_authority_key_id_ext(signing_cert);
        });
    REQUIRE(child_cert);
    REQUIRE(x509_name::equal(x509::get_subject(signing_cert), x509::get_issuer(child_cert)));

    auto const cert_text = x509::print_text(child_cert);
    REQUIRE_THAT(cert_text, ContainsSubstring("509v3 Authority Key Identifier: \n"));
}

TEST_CASE_METHOD(x509_builder_test, "X.509 Builder - Subject Alternative Names", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();

    SECTION("DNS Name")
    {
        auto cert = x509::selfsign(key, unittest::default_digest(), [this](x509::builder& builder) {
            builder.set_subject(name("Subject Alt Name"))
                .set_subject_alt_names_ext({
                    general_name::make_dns("example.com"),
                });
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Subject Alternative Name: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("DNS:example.com"));
    }

    SECTION("IP Address Name")
    {
        auto cert = x509::selfsign(key, unittest::default_digest(), [this](x509::builder& builder) {
            builder.set_subject(name("Subject Alt Name"))
                .set_subject_alt_names_ext({
                    general_name::make_ip("10.0.0.1"),
                    general_name::make_ip((in_addr) { .s_addr = htonl(INADDR_LOOPBACK) }),
                    general_name::make_ip("::ffff:10.0.0.1"),
                    general_name::make_ip(in6addr_loopback),
                });
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Subject Alternative Name: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("IP Address:10.0.0.1"));
        REQUIRE_THAT(cert_text, ContainsSubstring("IP Address:127.0.0.1"));
        REQUIRE_THAT(cert_text, ContainsSubstring("IP Address:0:0:0:0:0:FFFF:A00:1"));
        REQUIRE_THAT(cert_text, ContainsSubstring("IP Address:0:0:0:0:0:0:0:1"));
    }

    SECTION("Email Address Name")
    {
        auto cert = x509::selfsign(key, unittest::default_digest(), [this](x509::builder& builder) {
            builder.set_subject(name("Subject Alt Name"))
                .set_subject_alt_names_ext({
                    general_name::make_email("email@example.com"),
                });
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Subject Alternative Name: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("email:email@example.com"));
    }
}

TEST_CASE_METHOD(x509_builder_test, "X.509 Builder - From Request", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();
    auto const req = x509_req::sign(key, unittest::default_digest(), [this](x509_req::builder& builder) {
        builder.set_subject(name("Cert Request"))
            .set_key_usage_ext("digitalSignature, keyEncipherment, keyAgreement", /*critical=*/true)
            .set_ext_key_usage_ext("serverAuth", /*critical=*/true);
    });
    REQUIRE(req);

    SECTION("From Request No Copy")
    {
        auto cert = x509::builder(req, /*copy_exts=*/false).selfsign(key, EVP_sha256());
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);

        REQUIRE_THAT(cert_text, !ContainsSubstring("X509v3 Key Usage: critical\n"));
        REQUIRE_THAT(cert_text, !ContainsSubstring("Digital Signature, Key Encipherment, Key Agreement\n"));

        REQUIRE_THAT(cert_text, !ContainsSubstring("X509v3 Extended Key Usage: critical\n"));
        REQUIRE_THAT(cert_text, !ContainsSubstring("TLS Web Server Authentication\n"));
    }

    SECTION("From Request Copy")
    {
        auto cert = x509::builder(req, /*copy_exts=*/true).selfsign(key, EVP_sha256());
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);

        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Key Usage: critical\n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("Digital Signature, Key Encipherment, Key Agreement\n"));

        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Extended Key Usage: critical\n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("TLS Web Server Authentication\n"));
    }
}
