//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/asn1_time.hpp>
#include <cppossl/bignum.hpp>
#include <cppossl/error.hpp>

#include "common.hpp"

using namespace ossl;

using Catch::Matchers::ContainsSubstring;

static uint64_t constexpr v1 = 1234;
static uint64_t constexpr v2 = 4321;

TEST_CASE("bignum::from_integer", "[bignum][primitive]")
{
    owned<::BIGNUM> bn1 = bignum::make(v1);
    owned<::BIGNUM> bn2 = bignum::make(v1);
    owned<::BIGNUM> bn3 = bignum::make(v2);

    REQUIRE(BN_cmp(bn1.get(), bn2.get()) == 0);
    REQUIRE(BN_cmp(bn1.get(), bn3.get()) != 0);
}

TEST_CASE("bignum::from_asn1_integer()", "[bignum][primitive]")
{
    SECTION("valid ASN1 string type")
    {
        owned<::BIGNUM> bn1 = bignum::make(v1);
        owned<::ASN1_INTEGER> ai1 = asn1::integer::make(v1);
        owned<::BIGNUM> bn2 = bignum::make(asn1::integer::roref(ai1));

        REQUIRE(BN_cmp(bn1.get(), bn2.get()) == 0);
    }

    SECTION("invalid ASN1 string type")
    {

        owned<::ASN1_TIME> t = asn1::time::now();
        REQUIRE_THROWS(bignum::make(asn1::time::roref(t)));
    }
}

TEST_CASE("bignum::random", "[bignum][primitive]")
{
    REQUIRE_NOTHROW(bignum::random());
}

TEST_CASE("bignum::to_string", "[bignum][primitive]")
{
    owned<::BIGNUM> bn1 = bignum::make(v1);
    owned<::BIGNUM> bn2 = bignum::make(v1);
    owned<::BIGNUM> bn3 = bignum::make(v2);

    SECTION("to_dec_string")
    {
        REQUIRE(bignum::to_dec_string(bn1.get()) == bignum::to_dec_string(bn2.get()));
        REQUIRE(bignum::to_dec_string(bn1.get()) != bignum::to_dec_string(bn3.get()));
    }

    SECTION("to_hex_string")
    {
        REQUIRE(bignum::to_hex_string(bn1.get()) == bignum::to_hex_string(bn2.get()));
        REQUIRE(bignum::to_hex_string(bn1.get()) != bignum::to_hex_string(bn3.get()));
    }
}
