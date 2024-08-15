//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/x509_req_builder.hpp>

#include "common.hpp"

using namespace ossl;

using Catch::Matchers::ContainsSubstring;

struct x509_req_builder_test
{
    owned<::X509_NAME> name(std::string_view const& common_name)
    {
        return x509_name::build([&common_name](owned<::X509_NAME>& name) {
            x509_name::set_organization_name(name,
                {
                    "X.509 Request Builder",
                });
            x509_name::set_common_name(name, common_name);
        });
    }

    owned<::EVP_PKEY> const key { unittest::rsa_key_one.load() };
};

TEST_CASE_METHOD(x509_req_builder_test, "X.509 Request Builder - Sign", "[x509_req][builder]")
{
    auto const subject = name("Signed");
    auto req = x509_req::sign(
        key, unittest::default_digest(), [&subject](x509_req::builder& builder) { builder.set_subject(subject); });
    REQUIRE(req);
    REQUIRE(x509_name::equal(subject, x509_req::get_subject(req)));
    REQUIRE(x509_req::check_key(req, key));
}

TEST_CASE_METHOD(x509_req_builder_test, "X.509 Request Builder - Key Usage", "[x509_req][builder]")
{

    SECTION("Critical")
    {
        auto req = x509_req::sign(key, unittest::default_digest(), [this](x509_req::builder& builder) {
            builder.set_subject(name("Key Usage"))
                .set_key_usage_ext("digitalSignature, keyAgreement", /*critical=*/true);
        });
        REQUIRE(req);

        auto const req_text = x509_req::print_text(req);
        REQUIRE_THAT(req_text, ContainsSubstring("X509v3 Key Usage: critical\n"));
        REQUIRE_THAT(req_text, ContainsSubstring("Digital Signature, Key Agreement\n"));
    }

    SECTION("Non-Critical")
    {
        auto req = x509_req::sign(key, unittest::default_digest(), [this](x509_req::builder& builder) {
            builder.set_subject(name("Key Usage")).set_key_usage_ext("keyEncipherment, dataEncipherment");
        });
        REQUIRE(req);

        auto const req_text = x509_req::print_text(req);
        REQUIRE_THAT(req_text, ContainsSubstring("X509v3 Key Usage: \n"));
        REQUIRE_THAT(req_text, ContainsSubstring("Key Encipherment, Data Encipherment\n"));
    }

    SECTION("Invalid Usage String")
    {
        REQUIRE_THROWS_AS(x509_req::sign(key,
                              unittest::default_digest(),
                              [this](x509_req::builder& builder) {
                                  builder.set_subject(name("Key Usage"))
                                      .set_key_usage_ext("keyEncipherment, dataEncipherment, invalidUsage");
                              }),
            openssl_error);
    }
}

TEST_CASE_METHOD(x509_req_builder_test, "X.509 Request Builder - Extended Key Usage Identifier", "[x509_req][builder]")
{

    SECTION("Critical")
    {
        auto req = x509_req::sign(key, unittest::default_digest(), [this](x509_req::builder& builder) {
            builder.set_subject(name("Extended Key Usage")).set_ext_key_usage_ext("serverAuth", /*critical=*/true);
        });
        REQUIRE(req);

        auto const req_text = x509_req::print_text(req);
        REQUIRE_THAT(req_text, ContainsSubstring("X509v3 Extended Key Usage: critical\n"));
        REQUIRE_THAT(req_text, ContainsSubstring("TLS Web Server Authentication\n"));
    }

    SECTION("Non-Critical")
    {
        auto req = x509_req::sign(key, unittest::default_digest(), [this](x509_req::builder& builder) {
            builder.set_subject(name("Extended Key Usage")).set_ext_key_usage_ext("codeSigning, timeStamping");
        });
        REQUIRE(req);

        auto const req_text = x509_req::print_text(req);
        REQUIRE_THAT(req_text, ContainsSubstring("X509v3 Extended Key Usage: \n"));
        REQUIRE_THAT(req_text, ContainsSubstring("Code Signing, Time Stamping\n"));
    }

    SECTION("Invalid Usage String")
    {
        REQUIRE_THROWS_AS(
            x509_req::sign(key,
                unittest::default_digest(),
                [this](x509_req::builder& builder) {
                    builder.set_subject(name("Extended Key Usage")).set_ext_key_usage_ext("serverAuth, invalidUsage");
                }),
            openssl_error);
    }
}

TEST_CASE_METHOD(x509_req_builder_test, "X.509 Builder - Subject Alternative Names", "[x509_req][builder]")
{

    SECTION("DNS Name")
    {
        auto cert = x509_req::sign(key, unittest::default_digest(), [this](x509_req::builder& builder) {
            builder.set_subject(name("Subject Alt Name"))
                .set_subject_alt_names_ext({
                    general_name::make_dns("example.com"),
                });
        });
        REQUIRE(cert);

        auto const cert_text = x509_req::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Subject Alternative Name: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("DNS:example.com"));
    }

    SECTION("IP Address Name")
    {
        auto cert = x509_req::sign(key, unittest::default_digest(), [this](x509_req::builder& builder) {
            builder.set_subject(name("Subject Alt Name"))
                .set_subject_alt_names_ext({
                    general_name::make_ip("10.0.0.1"),
                    general_name::make_ip((in_addr) { .s_addr = htonl(INADDR_LOOPBACK) }),
                    general_name::make_ip("::ffff:10.0.0.1"),
                    general_name::make_ip(in6addr_loopback),
                });
        });
        REQUIRE(cert);

        auto const cert_text = x509_req::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Subject Alternative Name: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("IP Address:10.0.0.1"));
        REQUIRE_THAT(cert_text, ContainsSubstring("IP Address:127.0.0.1"));
        REQUIRE_THAT(cert_text, ContainsSubstring("IP Address:0:0:0:0:0:FFFF:A00:1"));
        REQUIRE_THAT(cert_text, ContainsSubstring("IP Address:0:0:0:0:0:0:0:1"));
    }

    SECTION("Email Address Name")
    {
        auto cert = x509_req::sign(key, unittest::default_digest(), [this](x509_req::builder& builder) {
            builder.set_subject(name("Subject Alt Name"))
                .set_subject_alt_names_ext({
                    general_name::make_email("email@example.com"),
                });
        });
        REQUIRE(cert);

        auto const cert_text = x509_req::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Subject Alternative Name: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("email:email@example.com"));
    }

    SECTION("UPN")
    {
        auto cert = x509_req::sign(key, unittest::default_digest(), [this](x509_req::builder& builder) {
            builder.set_subject(name("UPN Alt Name"))
                .set_subject_alt_names_ext({
                    general_name::make_upn("user@domain"),
                });
        });
        REQUIRE(cert);

        auto const cert_text = x509_req::print_text(cert);
        REQUIRE_THAT(cert_text, ContainsSubstring("X509v3 Subject Alternative Name: \n"));
        REQUIRE_THAT(cert_text, ContainsSubstring("othername: UPN::user@domain"));
    }
}
