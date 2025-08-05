//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <sstream>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/builder/x509_builder.hpp>
#include <cppossl/x509_crl_builder.hpp>

#include "common.hpp"

using namespace ossl;

using Catch::Matchers::ContainsSubstring;

struct x509_crl_builder_test
{
    static owned<::X509_NAME> name(std::string_view const& common_name)
    {
        return x509_name::build([&common_name](owned<::X509_NAME>& name) {
            x509_name::set_organization_name(name,
                {
                    "X.509 CRL Builder",
                });
            x509_name::set_common_name(name, common_name);
        });
    }

    static owned<::EVP_PKEY> const signing_key;
    static owned<::X509> const signing_cert;
};

owned<::EVP_PKEY> const x509_crl_builder_test::signing_key { unittest::rsa_key_one.load() };

owned<::X509> const x509_crl_builder_test::signing_cert { x509::v2::builder::selfsign(
    signing_key, unittest::default_digest(), [](x509::v2::builder::context& ctx) {
        set_subject(ctx, name("Signing Certificate"));
        set_public_key(ctx, signing_key);
        set_not_after(ctx, asn1::time::offset(std::chrono::hours(24) * 30));
        set_subject_key_id(ctx);
        set_key_usage(ctx, "nonRepudiation, keyCertSign, cRLSign");
    }) };

TEST_CASE_METHOD(x509_crl_builder_test, "X.509 CRL Builder - Sign", "[x509_crl][builder]")
{
    auto crl = x509_crl::builder::sign(
        signing_cert, signing_key, unittest::default_digest(), [](x509_crl::builder::context& ctx) {
            set_lastupdate(ctx, asn1::time::now());
            set_nextupdate(ctx, asn1::time::offset(std::chrono::hours(24) * 7));
        });
    REQUIRE(crl);
    REQUIRE_THAT(x509_crl::print_text(crl),
        ContainsSubstring(x509_name::print_text(x509::get_subject(signing_cert), XN_FLAG_COMPAT)));
}

TEST_CASE_METHOD(x509_crl_builder_test, "X.509 CRL Builder - Add Certificates", "[x509_crl][builder]")
{
    auto const childkey = unittest::rsa_key_two.load();
    std::vector<owned<::X509>> certs;
    for (uint i = 1; i <= 28; ++i)
    {
        std::stringstream ss;
        ss << "Child Cert " << i;
        certs.push_back(x509::v2::builder::sign(
            signing_cert, signing_key, unittest::default_digest(), [&childkey, &ss](x509::v2::builder::context& ctx) {
                set_subject(ctx, name(ss.str()));
                set_public_key(ctx, childkey);
                set_authority_key_id(ctx, signing_cert);
            }));
    }

    auto crl = x509_crl::builder::sign(
        signing_cert, signing_key, unittest::default_digest(), [&certs](x509_crl::builder::context& ctx) {
            set_lastupdate(ctx, asn1::time::now());
            set_nextupdate(ctx, asn1::time::offset(std::chrono::hours(24) * 7));

            int i = 0;
            for (auto const& cert : certs)
            {
                add(ctx, cert, asn1::time::offset(std::chrono::seconds(7 * ++i)), OCSP_REVOKED_STATUS_KEYCOMPROMISE);
            }
        });

    REQUIRE(crl);
    REQUIRE_THAT(x509_crl::print_text(crl),
        ContainsSubstring(x509_name::print_text(x509::get_subject(signing_cert), XN_FLAG_COMPAT)));
}
