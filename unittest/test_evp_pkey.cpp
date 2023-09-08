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

TEST_CASE("Load Private Key", "[pkey]")
{
    auto const testpemstr = ossl::unittest::get_test_pkey_data()[0];

    SECTION("Valid PEM String")
    {
        evp_pkey_t key;
        REQUIRE_NOTHROW(key = pem::loader<evp_pkey_t>::load(testpemstr));
        REQUIRE(key);
    }

    SECTION("Invalid PEM String")
    {
        REQUIRE_THROWS_AS(pem::loader<evp_pkey_t>::load(testpemstr.substr(0, 32)), openssl_error);
    }
}

TEST_CASE("Private Key Pemify", "[pkey]")
{
    auto const testpemstr = ossl::unittest::get_test_pkey_data()[0];
    evp_pkey_t key = pem::loader<evp_pkey_t>::load(testpemstr);
    REQUIRE(key);

    SECTION("Passwordless")
    {
        auto const keystr = pem::to_pem_string(key);
        REQUIRE_THAT(keystr, ContainsSubstring("BEGIN PRIVATE KEY"));

        evp_pkey_t load_key;
        REQUIRE_NOTHROW(load_key = pem::loader<evp_pkey_t>::load(keystr));
        REQUIRE(equal(key, load_key));
    }

    SECTION("Password Protected")
    {
        std::string const password = "qwertyuiop";
        auto const keystr = pem::to_pem_string(key, password);
        REQUIRE_THAT(keystr, ContainsSubstring("BEGIN ENCRYPTED PRIVATE KEY"));

        REQUIRE_THROWS_AS(pem::loader<evp_pkey_t>::load(keystr), openssl_error);

        evp_pkey_t load_key;
        REQUIRE_NOTHROW(load_key = pem::loader<evp_pkey_t>::load(keystr, password));
        REQUIRE(equal(key, load_key));
    }
}
