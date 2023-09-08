//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
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

TEST_CASE("Load CRL", "[crl]")
{

    SECTION("Valid PEM String")
    {
        x509_crl_t crl;
        REQUIRE_NOTHROW(crl = pem::loader<x509_crl_t>::load(testpemstr));
        REQUIRE(crl);
    }

    SECTION("Invalid PEM String")
    {
        REQUIRE_THROWS_AS(pem::loader<x509_crl_t>::load(testpemstr.substr(0, 32)), openssl_error);
    }
}

TEST_CASE("Pemify CRL", "[crl]")
{
    x509_crl_t crl = pem::loader<x509_crl_t>::load(testpemstr);
    REQUIRE(pem::to_pem_string(crl) == testpemstr);
}
