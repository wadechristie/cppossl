//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/error.hpp>
#include <cppossl/evp_pkey.hpp>
#include <cppossl/pem.hpp>

#include "common.hpp"

using namespace ossl;

using Catch::Matchers::ContainsSubstring;

TEST_CASE("evp_pkey_t - PEM", "[evp_pkey]")
{
    auto const testpemstr = ossl::unittest::get_test_pkey_data()[0];

    SECTION("Load Valid PEM")
    {
        owned<::EVP_PKEY> key;
        REQUIRE_NOTHROW(key = pem::load<::EVP_PKEY>(testpemstr));
        REQUIRE(key);
    }

    SECTION("Load Invalid PEM")
    {
        REQUIRE_THROWS_AS(pem::load<::EVP_PKEY>(testpemstr.substr(0, 32)), openssl_error);
    }

    SECTION("Passwordless PEM")
    {
        auto const orig_key = pem::load<::EVP_PKEY>(testpemstr);
        REQUIRE(orig_key);

        auto const pemstr = pem::to_pem_string(orig_key);
        REQUIRE_THAT(pemstr, ContainsSubstring("BEGIN PRIVATE KEY"));

        owned<::EVP_PKEY> load_from_pem;
        REQUIRE_NOTHROW(load_from_pem = pem::load<::EVP_PKEY>(pemstr));
        REQUIRE(evp_pkey::equal(orig_key, load_from_pem));
    }

    SECTION("Password Protected")
    {
        auto const orig_key = pem::load<::EVP_PKEY>(testpemstr);
        REQUIRE(orig_key);

        std::string const password = "qwertyuiop";
        auto const pemstr = pem::to_pem_string(orig_key, password);
        REQUIRE_THAT(pemstr, ContainsSubstring("BEGIN ENCRYPTED PRIVATE KEY"));

        REQUIRE_THROWS_AS(pem::load<::EVP_PKEY>(pemstr), openssl_error);
        REQUIRE_THROWS_AS(pem::load<::EVP_PKEY>(pemstr, "bad_password"), openssl_error);

        owned<::EVP_PKEY> load_key;
        REQUIRE_NOTHROW(load_key = pem::load<::EVP_PKEY>(pemstr, password));
        REQUIRE(evp_pkey::equal(orig_key, load_key));
    }
}

TEST_CASE("evp_pkey_t - retain()", "[evp_pkey]")
{
    auto const testpemstr = ossl::unittest::get_test_pkey_data()[0];

    owned<::EVP_PKEY> key;
    REQUIRE_FALSE(key);

    {
        auto const innerkey = pem::load<::EVP_PKEY>(testpemstr);
        REQUIRE(innerkey);
        REQUIRE_NOTHROW(key = evp_pkey::retain(innerkey));
    }

    REQUIRE(key);
}
