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
        evp_pkey_t key;
        REQUIRE_NOTHROW(key = pem::load<evp_pkey_t>(testpemstr));
        REQUIRE(key);
    }

    SECTION("Load Invalid PEM")
    {
        REQUIRE_THROWS_AS(pem::load<evp_pkey_t>(testpemstr.substr(0, 32)), openssl_error);
    }

    SECTION("Passwordless PEM")
    {
        evp_pkey_t const orig_key = pem::load<evp_pkey_t>(testpemstr);
        REQUIRE(orig_key);

        auto const pemstr = pem::to_pem_string(orig_key);
        REQUIRE_THAT(pemstr, ContainsSubstring("BEGIN PRIVATE KEY"));

        evp_pkey_t load_from_pem;
        REQUIRE_NOTHROW(load_from_pem = pem::load<evp_pkey_t>(pemstr));
        REQUIRE(equal(orig_key, load_from_pem));
    }

    SECTION("Password Protected")
    {
        evp_pkey_t const orig_key = pem::load<evp_pkey_t>(testpemstr);
        REQUIRE(orig_key);

        std::string const password = "qwertyuiop";
        auto const pemstr = pem::to_pem_string(orig_key, password);
        REQUIRE_THAT(pemstr, ContainsSubstring("BEGIN ENCRYPTED PRIVATE KEY"));

        REQUIRE_THROWS_AS(pem::load<evp_pkey_t>(pemstr), openssl_error);
        REQUIRE_THROWS_AS(pem::load<evp_pkey_t>(pemstr, "bad_password"), openssl_error);

        evp_pkey_t load_key;
        REQUIRE_NOTHROW(load_key = pem::load<evp_pkey_t>(pemstr, password));
        REQUIRE(equal(orig_key, load_key));
    }
}

TEST_CASE("evp_pkey_t - new_ref()", "[evp_pkey]")
{
    auto const testpemstr = ossl::unittest::get_test_pkey_data()[0];

    evp_pkey_t key;
    REQUIRE_FALSE(key);

    {
        auto const innerkey = pem::load<evp_pkey_t>(testpemstr);
        REQUIRE(innerkey);
        REQUIRE_NOTHROW(key = new_ref(innerkey));
    }

    REQUIRE(key);
}
