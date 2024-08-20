//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/error.hpp>
#include <cppossl/pem.hpp>
#include <cppossl/x509.hpp>
#include <cppossl/x509_builder.hpp>
#include <cppossl/x509_name.hpp>

#include "common.hpp"

using namespace ossl;

using Catch::Matchers::ContainsSubstring;

namespace {

time_t constexpr not_befor = 1694011572;
time_t constexpr not_after = 1694616372;
auto const serial_hex = "8CE97DE51458BCB9";
std::string const pemstr = "-----BEGIN CERTIFICATE-----\n"
                           "MIICuDCCAaCgAwIBAgIJAIzpfeUUWLy5MA0GCSqGSIb3DQEBCwUAMA8xDTALBgNV\n"
                           "BAMMBFRlc3QwHhcNMjMwOTA2MTQ0NjEyWhcNMjMwOTEzMTQ0NjEyWjAPMQ0wCwYD\n"
                           "VQQDDARUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwiYzhvS5\n"
                           "b4Cya71qj77melathH69JuddKtt+cAt+C5ogu9PYtaVwOJzQI+sQa9d/j2AlbSy+\n"
                           "KwqJmsXNOTRjy/C6VTzYhVC02Oo6QzipejIk0XyO1qOawm6l00CPVpS6PsSxcKuV\n"
                           "c0Ah9yAT04wkr7TSaA16Fb00fmIvwPKDHYStv6iPW0drfqokpTAtN8UVA6ypmaLi\n"
                           "cuSOHtlWWUIZNlb/FJoH/2QCpt4Ju/f1wMqJip4/4BX3+YLhI1NALYFKSDPYBXQB\n"
                           "JXxS/el5mBPv/2AJN4y4U8JX1apv5zmY9s5ZBnsO4xiM4kn3eSVEz/6wt8cTWbbE\n"
                           "LvKujx8r8F6mQwIDAQABoxcwFTATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG\n"
                           "9w0BAQsFAAOCAQEAvGyjAPkOExA9xKxDsZwU6aMFy/ZjE6xPWF2jfoqNGK9qvsqo\n"
                           "iTfO+ucwN5+YOB93rs2lx+1dSM+Mun3RSBpcaAM/0UB6k/0O6NHKCEaowiY3G18n\n"
                           "fUMvHWFYdJLkfI1Q2MsuWpBEHr4BMyXwdFniA8VL9swJ5YUQatMXMsf7yLSyon3Y\n"
                           "smEPyBJnXzUIN0pIdwiRqlHH6xU406bKCAniZXBUgRS1ff++J0fyMiR1nu+Fzo9N\n"
                           "bWJ06324fYZ9mkcur9QkbcY9DLWK+P2wGo7WbOb2rKGocquidpCUgqsI0Kmi4BTC\n"
                           "C5lpnErdR/M/Rb0s/TZBeHcPRzZE/PUV1gNixQ==\n"
                           "-----END CERTIFICATE-----";

} // namespace

TEST_CASE("Load X.509 PEM", "[x509][pem]")
{
    SECTION("Valid PEM String")
    {
        owned<::X509> x509;
        REQUIRE_NOTHROW(x509 = pem::load<::X509>(pemstr));
        REQUIRE(x509);

        REQUIRE(x509::get_not_before(x509) == not_befor);
        REQUIRE(x509::get_not_after(x509) == not_after);
        REQUIRE(x509::get_serial_number_hex(x509) == serial_hex);
    }

    SECTION("Invalid PEM String")
    {
        REQUIRE_THROWS_AS(pem::load<::X509>(pemstr.substr(0, 32)), openssl_error);
    }
}

TEST_CASE("X.509 - retain()", "[x509]")
{
    owned<::X509> cert;
    REQUIRE_FALSE(cert);

    {
        auto const innercert = pem::load<::X509>(pemstr);
        REQUIRE(innercert);
        REQUIRE_NOTHROW(cert = x509::retain(innercert));
    }

    REQUIRE(cert);
}

TEST_CASE("X.509 - equal()", "[x509]")
{
    auto const key = unittest::rsa_key_one.load();
    auto const subject = x509_name::build([](auto& name) { x509_name::set_common_name(name, "Equality Test"); });
    owned<::X509> cert = x509::selfsign(
        key, unittest::default_digest(), [&subject](x509::builder& builder) { builder.set_subject(subject); });
    REQUIRE(cert);

    std::string cert_as_pem;
    REQUIRE_NOTHROW(cert_as_pem = pem::to_pem_string(cert));

    REQUIRE(ossl::x509::equal(cert, pem::load<::X509>(cert_as_pem)));
    REQUIRE_FALSE(ossl::x509::equal(cert, pem::load<::X509>(pemstr)));
}
