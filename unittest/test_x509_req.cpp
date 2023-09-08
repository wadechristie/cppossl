//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>

#include <cppossl/error.hpp>
#include <cppossl/pem.hpp>
#include <cppossl/x509_req.hpp>

using namespace ossl;

namespace {

std::string const testpemstr = "-----BEGIN CERTIFICATE REQUEST-----\n"
                               "MIIDPTCCAiUCAQAwgYsxCzAJBgNVBAYTAlVTMRcwFQYKCZImiZPyLGQBGRYHZXhh\n"
                               "bXBsZTETMBEGCgmSJomT8ixkARkWA2NvbTEQMA4GA1UECgwHY2VydGlmeTERMA8G\n"
                               "A1UECwwIdW5pdHRlc3QxKTAnBgNVBAMMIFJlcXVlc3QgQnVpbGRlciBTdWJqZWN0\n"
                               "IEFsdCBOYW1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlOzAARtE\n"
                               "6CbvnUbX3euF3z21HuYjIl5R4fFFH8rL9mS+0v4yGizK2lKQPkrm/qaSL7k9eljU\n"
                               "pSRkjL1s3NNVDuCpaCc13+1EpGVd/greVKPQPgAC37vWWhUaNobymjA1hcQZHd4B\n"
                               "4lF/CxQmRXUSlbtW+KtGxwuYZDPY0FVswofxfN5yn5TbHlCqIJlEZklyw6NtKCPe\n"
                               "Cd+Q+S6l3g1Y/MQyGHXiNzbjDMUVZb6aAusi1aZQnwRjgXL5tAD6yf1rQBK7f4db\n"
                               "e+rs7lpfEwCgAH94pspu6NldvjYNDmKhfpnUm+2A63QvdJSIghWPzdCaemx+7qhW\n"
                               "8Dkl9ZDYczr+gQIDAQABoGwwagYJKoZIhvcNAQkOMV0wWzBZBgNVHREEUjBQggtl\n"
                               "eGFtcGxlLmNvbYcECgAAAYcEfwAAAYcQAAAAAAAAAAAAAP//CgAAAYcQAAAAAAAA\n"
                               "AAAAAAAAAAAAAYERZW1haWxAZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB\n"
                               "AA+RsiUUJ9WgRBhrkl9WMuGihJGJm0bR7Rz2qYszRe6FV9Texyt7/N8PUEGoysyI\n"
                               "GLp+xd8f3UtD9hlutxpcFnHXxg/3kqq2V9xGGKyxb5a2zsFxD0Gy6x4p88gVzdhO\n"
                               "m//eesxAL5UY5N//XC9dH7zoFxccPaV1HMKIa8bHiyoW+kve1H5LL75NQP4SsoD9\n"
                               "Y5GD0VWGNPYOpnEdUB+KWsahVcyIIHqJe45E8Ni5W18z9FTBUKs9hUdEd7/1KKK3\n"
                               "5yrWU9M3UKaiDc/JJzABOWbQZ88xojBqHqFngpg9Rdubvj0FiV8v2vfHI9ZeiAJR\n"
                               "ii0TxNu3/xd0MjWH5RGoYko=\n"
                               "-----END CERTIFICATE REQUEST-----\n";

} // namespace

TEST_CASE("Load CSR", "[x509][req][ossl]")
{

    SECTION("Valid PEM String")
    {
        x509_req_t req;
        REQUIRE_NOTHROW(req = pem::load<x509_req_t>(testpemstr));
        REQUIRE(req);
    }

    SECTION("Invalid PEM String")
    {
        REQUIRE_THROWS_AS(pem::load<x509_req_t>(testpemstr.substr(0, 32)), openssl_error);
    }
}

TEST_CASE("Pemify CRL", "[x509][req][ossl]")
{
    x509_req_t req = pem::load<x509_req_t>(testpemstr);
    REQUIRE(pem::to_pem_string(req) == testpemstr);
}
