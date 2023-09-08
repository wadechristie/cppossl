//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>

#include <cppossl/raii.hpp>
#include <cppossl/stack.hpp>

TEST_CASE("OpenSSL Stack Helpers", "[stack]")
{
    auto sk = ossl::general_name_sk_t::make();
    REQUIRE(ossl::stack::empty(sk));

    SECTION("Push")
    {
        constexpr size_t count = 10;
        for (size_t i = 0; i < count; ++i)
        {
            REQUIRE_NOTHROW(ossl::stack::push(sk, ossl::general_name_t::make()));
            REQUIRE(ossl::stack::size(sk) == (i + 1));
        }
    }

    SECTION("Pop")
    {
        REQUIRE_NOTHROW(ossl::stack::push(sk, ossl::general_name_t::make()));
        REQUIRE_FALSE(ossl::stack::empty(sk));

        ossl::general_name_t elem;
        REQUIRE_NOTHROW(elem = ossl::stack::pop(sk));
        REQUIRE(ossl::stack::empty(sk));
        REQUIRE(elem);
    }
}
