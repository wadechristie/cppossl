//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>

#include <cppossl/asn1_bit_string.hpp>
#include <cppossl/asn1_string.hpp>

#include "common.hpp"

using namespace ossl;

TEST_CASE("asn1::string", "[asn1_string]")
{
    SECTION("ASCII String")
    {
        REQUIRE_NOTHROW(asn1::string::make<asn1::IA5STRING>("Ascii String"));
    }

    SECTION("UTF8 String")
    {
        REQUIRE_NOTHROW(asn1::string::make<asn1::UTF8STRING>("UFT8 String €"));
    }

    SECTION("Invalid String")
    {
        auto bitstr = make<asn1::BIT_STRING>();
        REQUIRE_THROWS_AS(asn1::string::set(bitstr, "string value"), std::runtime_error);
    }
}
