//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/error.hpp>

#include "common.hpp"

using Catch::Matchers::ContainsSubstring;

TEST_CASE("openssl_error")
{
    ossl::openssl_error error(1, "Test exception.");
    REQUIRE(error.what() == std::string("OpenSSL error: 1 - error:00000001:lib(0)::reason(1) - Test exception."));
}
