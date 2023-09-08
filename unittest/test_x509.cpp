//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/error.hpp>
#include <cppossl/pem.hpp>
#include <cppossl/x509.hpp>

using namespace ossl;

using Catch::Matchers::ContainsSubstring;

TEST_CASE("Load X.509", "[x509]")
{
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

    SECTION("Valid PEM String")
    {
        x509_t x509;
        REQUIRE_NOTHROW(x509 = pem::loader<x509_t>::load(pemstr));
        REQUIRE(x509);

        REQUIRE(get_not_before(x509) == 1694011572);
        REQUIRE(get_not_after(x509) == 1694616372);
        REQUIRE(get_serial_number_hex(x509) == "8CE97DE51458BCB9");
    }

    SECTION("Invalid PEM String")
    {
        REQUIRE_THROWS_AS(pem::loader<x509_t>::load(pemstr.substr(0, 32)), openssl_error);
    }
}
