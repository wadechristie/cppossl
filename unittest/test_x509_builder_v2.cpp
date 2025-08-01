//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/builder/x509_builder.hpp>

#include "common.hpp"

using Catch::Matchers::ContainsSubstring;

using namespace ossl;

namespace {

owned<::X509_NAME> name(std::string_view common_name)
{
    return x509_name::build([&common_name](owned<::X509_NAME>& name) {
        x509_name::set_organization_name(name,
            {
                "X.509 Builder",
            });
        x509_name::set_common_name(name, common_name);
    });
}

}

TEST_CASE("v2 X.509 Builder - Selfsign", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();
    auto const subject = name("Self-Signed");

    auto cert = x509::v2::builder::selfsign(key,
        unittest::default_digest(),
        [&subject](x509::v2::builder::context& ctx) { x509::v2::builder::set_subject(ctx, subject); });
    REQUIRE(cert);

    INFO(x509::print_text(cert));
    REQUIRE(x509_name::equal(subject, x509::get_subject(cert)));
    REQUIRE(x509_name::equal(subject, x509::get_issuer(cert)));
    // Default notBefore/notAfter is now
    REQUIRE(x509::get_not_before(cert) == x509::get_not_after(cert));
    REQUIRE(x509::check_key(cert, key));
}

TEST_CASE("v2 X.509 Builder - Basic Constraints", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();

    SECTION("Basic Constraints - CA:TRUE")
    {
        auto cert = x509::v2::builder::selfsign(key, unittest::default_digest(), [](x509::v2::builder::context& ctx) {
            set_subject(ctx, name("Basic Constraints"));
            set_basic_constraints(ctx, true);
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Basic Constraints: critical\n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("CA:TRUE\n"));
    }

    SECTION("Basic Constraints - CA:TRUE, pathlen=1")
    {
        auto cert = x509::v2::builder::selfsign(key, unittest::default_digest(), [](x509::v2::builder::context& ctx) {
            set_subject(ctx, name("Basic Constraints"));
            set_basic_constraints(ctx, /*ca=*/true, /*pathlen=*/1);
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Basic Constraints: critical\n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("CA:TRUE, pathlen:1\n"));
    }

    SECTION("Basic Constraints - CA:FALSE")
    {
        auto cert = x509::v2::builder::selfsign(key, unittest::default_digest(), [](x509::v2::builder::context& ctx) {
            set_subject(ctx, name("Basic Constraints"));
            set_basic_constraints(ctx, /*ca=*/false);
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Basic Constraints: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("CA:FALSE\n"));
    }
}

TEST_CASE("v2 X.509 Builder - Key Usage", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();

    SECTION("Critical")
    {
        auto cert = x509::v2::builder::selfsign(key, unittest::default_digest(), [](x509::v2::builder::context& ctx) {
            set_subject(ctx, name("Key Usage"));
            set_key_usage(ctx, "critical, digitalSignature, keyAgreement");
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Key Usage: critical\n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("Digital Signature, Key Agreement\n"));
    }

    SECTION("Non-Critical")
    {
        auto cert = x509::v2::builder::selfsign(key, unittest::default_digest(), [](x509::v2::builder::context& ctx) {
            set_subject(ctx, name("Key Usage"));
            set_key_usage(ctx, "keyEncipherment, dataEncipherment");
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Key Usage: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("Key Encipherment, Data Encipherment\n"));
    }

    SECTION("Invalid Usage String")
    {
        REQUIRE_THROWS_AS(x509::v2::builder::selfsign(key,
                              unittest::default_digest(),
                              [](x509::v2::builder::context& ctx) {
                                  set_subject(ctx, name("Key Usage"));
                                  set_key_usage(ctx, "keyEncipherment, dataEncipherment, invalidUsage");
                              }),
            openssl_error);
    }
}

TEST_CASE("X.509 Builder - Extended Key Usage Identifier", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();

    SECTION("Critical")
    {
        auto cert = x509::v2::builder::selfsign(key, unittest::default_digest(), [](x509::v2::builder::context& ctx) {
            set_subject(ctx, name("Extended Key Usage"));
            set_ext_key_usage(ctx, "critical,serverAuth");
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Extended Key Usage: critical\n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("TLS Web Server Authentication\n"));
    }

    SECTION("Non-Critical")
    {
        auto cert = x509::v2::builder::selfsign(key, unittest::default_digest(), [](x509::v2::builder::context& ctx) {
            set_subject(ctx, name("Extended Key Usage"));
            set_ext_key_usage(ctx, "codeSigning, timeStamping");
        });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Extended Key Usage: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("Code Signing, Time Stamping\n"));
    }

    SECTION("Invalid Usage String")
    {
        REQUIRE_THROWS_AS(x509::v2::builder::selfsign(key,
                              EVP_sha256(),
                              [](x509::v2::builder::context& ctx) {
                                  set_subject(ctx, name("Extended Key Usage"));
                                  set_ext_key_usage(ctx, "serverAuth, invalidUsage");
                              }),
            openssl_error);
    }
}

TEST_CASE("v2 X.509 Builder - Subject Key Identifier", "[x509][builder]")
{
    auto const key = unittest::rsa_key_one.load();

    SECTION("Subject Key Identifier")
    {
        auto cert
            = x509::v2::builder::selfsign(key, unittest::default_digest(), [&key](x509::v2::builder::context& ctx) {
                  set_subject(ctx, name("Subject Key Identifier"));
                  set_public_key(ctx, key);
                  set_subject_key_id(ctx);
              });
        REQUIRE(cert);

        auto const cert_text = x509::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("509v3 Subject Key Identifier: \n"));
    }

    SECTION("Public Key Not Set")
    {
        REQUIRE_THROWS_AS((void)x509::v2::builder::selfsign(key,
                              EVP_sha256(),
                              [](x509::v2::builder::context& ctx) {
                                  set_subject(ctx, name("Subject Key Identifier"));
                                  set_subject_key_id(ctx);
                              }),
            std::system_error);
    }
}

TEST_CASE("X.509 Builder - Authority Key Identifier", "[x509][builder]")
{
    auto const signing_key = unittest::rsa_key_one.load();
    auto const child_key = unittest::rsa_key_two.load();

    auto signing_cert = x509::v2::builder::selfsign(
        signing_key, unittest::default_digest(), [&signing_key](x509::v2::builder::context& ctx) {
            set_subject(ctx, name("Signing Cert"));
            set_public_key(ctx, signing_key);
            set_basic_constraints(ctx, /*ca=*/true, /*pathlen=*/0);
            set_subject_key_id(ctx);
        });
    REQUIRE(signing_cert);

    auto child_cert = x509::v2::builder::sign(signing_cert,
        signing_key,
        unittest::default_digest(),
        [&signing_cert, &child_key](x509::v2::builder::context& ctx) {
            set_subject(ctx, name("Child Cert"));
            set_public_key(ctx, child_key);
            set_authority_key_id(ctx, signing_cert);
        });
    REQUIRE(child_cert);
    REQUIRE(x509_name::equal(x509::get_subject(signing_cert), x509::get_issuer(child_cert)));

    auto const cert_text = x509::print_text(child_cert);
    REQUIRE_THAT(cert_text, ContainsSubstring("509v3 Authority Key Identifier: \n"));
}
