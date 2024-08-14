//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/asn1_bit_string.hpp>
#include <cppossl/error.hpp>

#include "common.hpp"

using namespace ossl;

TEST_CASE("asn1::bit_string", "[asn1_bit_string]")
{
    owned<::ASN1_BIT_STRING> bits;
    REQUIRE_NOTHROW(bits = make<::ASN1_BIT_STRING>());
    REQUIRE(bits);

    REQUIRE_FALSE(asn1::bit_string::is_set(bits, 0));
    REQUIRE_FALSE(asn1::bit_string::is_set(bits, 1));
    REQUIRE_FALSE(asn1::bit_string::is_set(bits, 2));
    REQUIRE_FALSE(asn1::bit_string::is_set(bits, 3));

    REQUIRE_NOTHROW(asn1::bit_string::set(bits, 0));
    REQUIRE_NOTHROW(asn1::bit_string::set(bits, 2));

    REQUIRE(asn1::bit_string::is_set(bits, 0));
    REQUIRE_FALSE(asn1::bit_string::is_set(bits, 1));
    REQUIRE(asn1::bit_string::is_set(bits, 2));
    REQUIRE_FALSE(asn1::bit_string::is_set(bits, 3));

    REQUIRE_NOTHROW(asn1::bit_string::clear(bits, 0));

    REQUIRE_FALSE(asn1::bit_string::is_set(bits, 0));
    REQUIRE_FALSE(asn1::bit_string::is_set(bits, 1));
    REQUIRE(asn1::bit_string::is_set(bits, 2));
    REQUIRE_FALSE(asn1::bit_string::is_set(bits, 3));
}
