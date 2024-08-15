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

TEST_CASE("asn1::time::from_unix()", "[asn1_time]")
{
    time_t const now = time(nullptr);

    owned<::ASN1_TIME> t;
    REQUIRE_NOTHROW(t = asn1::time::from_unix(now));
    REQUIRE(t);

    time_t back_to_unix = 0;
    REQUIRE_NOTHROW(back_to_unix = asn1::time::to_unix(t));
    REQUIRE(now == back_to_unix);
}

TEST_CASE("asn1::time::cmp()", "[asn1_time]")
{
    time_t const now = time(nullptr);
    time_t const now_plus_test_seconds = now + 10;

    owned<::ASN1_TIME> time_now;
    REQUIRE_NOTHROW(time_now = asn1::time::from_unix(now));
    REQUIRE(time_now);

    owned<::ASN1_TIME> time_ten_sec_from_now;
    REQUIRE_NOTHROW(time_ten_sec_from_now = asn1::time::from_unix(now_plus_test_seconds));
    REQUIRE(time_ten_sec_from_now);

    REQUIRE(asn1::time::cmp(time_now, asn1::time::dup(time_now)) == 0);
    REQUIRE(asn1::time::cmp(time_ten_sec_from_now, asn1::time::dup(time_ten_sec_from_now)) == 0);
    REQUIRE(asn1::time::cmp(time_now, time_ten_sec_from_now) < 0);
    REQUIRE(asn1::time::cmp(time_ten_sec_from_now, time_now) > 0);
}

TEST_CASE("asn1::time::set_offset()", "[asn1_time]")
{
    time_t const now = time(nullptr);
    time_t const now_plus_test_seconds = now + 10;

    owned<::ASN1_TIME> time_now;
    REQUIRE_NOTHROW(time_now = asn1::time::from_unix(now));
    REQUIRE(time_now);

    owned<::ASN1_TIME> ten_sec_from_now;
    REQUIRE_NOTHROW(ten_sec_from_now = asn1::time::from_unix(now));
    REQUIRE(ten_sec_from_now);

    REQUIRE_NOTHROW(asn1::time::set_offset(ten_sec_from_now, std::chrono::seconds(10)));

    REQUIRE(now_plus_test_seconds == asn1::time::to_unix(ten_sec_from_now));
}

TEST_CASE("asn1::time::set_unix()", "[asn1_time]")
{
    time_t const now = time(nullptr);
    time_t const now_plus_test_seconds = now + 10;

    owned<::ASN1_TIME> time_now;
    REQUIRE_NOTHROW(time_now = asn1::time::from_unix(now));
    REQUIRE(time_now);

    owned<::ASN1_TIME> ten_sec_from_now;
    REQUIRE_NOTHROW(ten_sec_from_now = asn1::time::dup(time_now));
    REQUIRE(ten_sec_from_now);

    REQUIRE_NOTHROW(asn1::time::set_unix(ten_sec_from_now, now_plus_test_seconds));

    REQUIRE(now_plus_test_seconds == asn1::time::to_unix(ten_sec_from_now));
}
