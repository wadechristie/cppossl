//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>

#include <cppossl/asn1_string.hpp>
#include <cppossl/raii.hpp>
#include <cppossl/stack.hpp>

#include "common.hpp"

using namespace ossl;

TEST_CASE("OpenSSL Stack Wrapper", "[stack]")
{
    auto sk = sk::make<::ASN1_STRING>();
    REQUIRE(sk.size() == 0);
    REQUIRE(sk.empty());

    SECTION("Push")
    {
        constexpr size_t count = 10;
        for (size_t i = 1; i <= count; ++i)
        {
            REQUIRE_NOTHROW(sk.push(asn1::string::make<asn1::UTF8STRING>("String Value")));
            REQUIRE(sk.size() == i);
        }

        REQUIRE(sk.size() > 0);
        REQUIRE_FALSE(sk.empty());
    }

    SECTION("Unshift")
    {
        constexpr size_t count = 10;
        for (size_t i = 1; i <= count; ++i)
        {
            REQUIRE_NOTHROW(sk.unshift(asn1::string::make<asn1::UTF8STRING>("String Value")));
            REQUIRE(sk.size() == i);
        }

        REQUIRE(sk.size() > 0);
        REQUIRE_FALSE(sk.empty());
    }

    SECTION("Pop")
    {
        REQUIRE_NOTHROW(sk.push(asn1::string::make<asn1::UTF8STRING>("String Value")));
        REQUIRE_FALSE(sk.empty());

        ossl::owned<::ASN1_STRING> s;
        REQUIRE_NOTHROW(s = sk.pop());
        REQUIRE(sk.empty());
        REQUIRE(s);
    }

    SECTION("Shift")
    {
        REQUIRE_NOTHROW(sk.push(asn1::string::make<asn1::UTF8STRING>("String Value")));
        REQUIRE_FALSE(sk.empty());

        ossl::owned<::ASN1_STRING> s;
        REQUIRE_NOTHROW(s = sk.shift());
        REQUIRE(sk.empty());
        REQUIRE(s);
    }

    SECTION("Iterate")
    {
        constexpr size_t count = 10;
        for (size_t i = 1; i <= count; ++i)
        {
            REQUIRE_NOTHROW(sk.push(asn1::string::make<asn1::UTF8STRING>("String Value")));
            REQUIRE(sk.size() == i);
        }

        size_t n = 0;
        for (auto const& elem : sk)
        {
            n += 1;
            REQUIRE(elem != nullptr);
        }

        REQUIRE(count == n);
    }
}
