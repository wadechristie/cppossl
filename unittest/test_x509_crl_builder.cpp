//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <sstream>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/x509_builder.hpp>
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

owned<::X509> const x509_crl_builder_test::signing_cert { x509::selfsign(
    signing_key, unittest::default_digest(), [](x509::builder& builder) {
        builder.set_subject(name("Signing Certificate"))
            .set_public_key(signing_key)
            .set_not_after(asn1_time::offset(std::chrono::hours(24) * 30))
            .set_subject_key_id_ext()
            .set_key_usage_ext("nonRepudiation, keyCertSign, cRLSign");
    }) };

TEST_CASE_METHOD(x509_crl_builder_test, "X.509 CRL Builder - Sign", "[x509_crl][builder]")
{
    auto crl = x509_crl::sign(signing_cert, signing_key, unittest::default_digest(), [](x509_crl::builder& builder) {
        builder.set_lastupdate(asn1_time::now()).set_nextupdate(asn1_time::offset(std::chrono::hours(24) * 7));
    });
    REQUIRE(crl);
    REQUIRE_THAT(x509_crl::print_text(crl),
        ContainsSubstring(x509_name::print_text(x509::get_subject(signing_cert), XN_FLAG_COMPAT)));
}

TEST_CASE_METHOD(x509_crl_builder_test, "X.509 CRL Builder - Add Certificates", "[x509_crl][builder]")
{
    x509_crl::builder builder;
    builder.set_lastupdate(asn1_time::now());
    builder.set_nextupdate(asn1_time::offset(std::chrono::hours(24) * 7));

    auto const childkey = unittest::rsa_key_two.load();
    std::vector<owned<::X509>> certs;
    for (uint i = 1; i <= 28; ++i)
    {
        std::stringstream ss;
        ss << "Child Cert " << i;
        certs.push_back(x509::sign(
            signing_cert, signing_key, unittest::default_digest(), [this, &childkey, &ss](x509::builder& builder) {
                builder.set_subject(name(ss.str())).set_public_key(childkey).set_authority_key_id_ext(signing_cert);
            }));
        builder.add(
            *certs.crbegin(), asn1_time::offset(std::chrono::seconds(7 * i)), OCSP_REVOKED_STATUS_KEYCOMPROMISE);
    }

    auto const crl = builder.sign(signing_cert, signing_key, unittest::default_digest());
    REQUIRE(crl);
    REQUIRE_THAT(x509_crl::print_text(crl),
        ContainsSubstring(x509_name::print_text(x509::get_subject(signing_cert), XN_FLAG_COMPAT)));
}
