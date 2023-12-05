//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/asn1_time.hpp>
#include <cppossl/error.hpp>

#include "common.hpp"

using namespace ossl;

using Catch::Matchers::ContainsSubstring;

TEST_CASE("asn1_time::from_unix()", "[asn1_time]")
{
    time_t const now = time(nullptr);

    owned<::ASN1_TIME> t;
    REQUIRE_NOTHROW(t = asn1_time::from_unix(now));
    REQUIRE(t);

    time_t back_to_unix = 0;
    REQUIRE_NOTHROW(back_to_unix = asn1_time::to_unix(t));
    REQUIRE(now == back_to_unix);
}
