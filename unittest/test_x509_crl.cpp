//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>

#include <cppossl/error.hpp>
#include <cppossl/pem.hpp>
#include <cppossl/x509_crl.hpp>

using namespace ossl;

namespace {

std::string const testpemstr = "-----BEGIN X509 CRL-----\n"
                               "MIIB+zCB5AIBATANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMCVVMxFzAVBgoJ\n"
                               "kiaJk/IsZAEZFgdleGFtcGxlMRMwEQYKCZImiZPyLGQBGRYDY29tMRAwDgYDVQQK\n"
                               "DAdjZXJ0aWZ5MREwDwYDVQQLDAh1bml0dGVzdDEZMBcGA1UECwwQWDUwOSBDUkwg\n"
                               "QnVpbGRlcjEXMBUGA1UEAwwOQ0EgQ2VydGlmaWNhdGUXDTIzMDkwNTE4MzExMVow\n"
                               "KjAoAgkA4TxrO02Q/VcXDTIzMDkwNTE4MzExMVowDDAKBgNVHRUEAwoBADANBgkq\n"
                               "hkiG9w0BAQsFAAOCAQEAnN99fyEwALvCo9Lg23dsWaNCEtVSotnscY98vG+iODTk\n"
                               "hoNrsL2j8D58D37d2WzfFM6gFZbRpCUPvELkrkhs10ZLIxBZ7DiMBTPU9zhTrks0\n"
                               "Wm5CEhJmZV1flH4M6iYOQgearh0Cfnf0NE/80Gd7KmTE8dm9BSpcM7oW3nPbN5YY\n"
                               "RLjCFfq3Gk2+OGRIjWmrV7FrsbCrZxOqoBJDiysTqMSXOGaIJdQg61vXKJ5H2HvY\n"
                               "PWCcHrTSL9ypT55TS7NUHnwBA3NPRVMK3GqJ6uX/QGmGCISh89hkGzG3Qb59Z6lA\n"
                               "OnaZCReNt9iL4vH4b9Rf21d2gKdlvBHzusZjrDkqNg==\n"
                               "-----END X509 CRL-----\n";

} // namespace

TEST_CASE("X.509 CRL - Load", "[crl][pem]")
{

    SECTION("Valid PEM String")
    {
        owned<::X509_CRL> crl;
        REQUIRE_NOTHROW(crl = pem::load<::X509_CRL>(testpemstr));
        REQUIRE(crl);
    }

    SECTION("Invalid PEM String")
    {
        REQUIRE_THROWS_AS(pem::load<::X509_CRL>(testpemstr.substr(0, 32)), openssl_error);
    }
}

TEST_CASE("X.509 CRL - Convert to PEM", "[crl][pem]")
{
    auto crl = pem::load<::X509_CRL>(testpemstr);
    REQUIRE(pem::to_pem_string(crl) == testpemstr);
}

TEST_CASE("X.509 CRL - Retain", "[crl]")
{
    owned<::X509_CRL> crl;
    REQUIRE_FALSE(crl);

    {
        auto innercrl = pem::load<::X509_CRL>(testpemstr);
        REQUIRE(innercrl);
        REQUIRE_NOTHROW(crl = x509_crl::retain(innercrl));
    }

    REQUIRE(crl);
}
