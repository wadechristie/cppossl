//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cppossl/error.hpp>

#include "common.hpp"

using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::MessageMatches;

namespace _ {

class assertion_error : public std::exception
{
public:
    inline explicit assertion_error(std::string msg)
        : _msg(std::move(msg))
    {
    }

    ~assertion_error() = default;

    assertion_error(assertion_error&&) = default;
    assertion_error& operator=(assertion_error&&) = default;

    assertion_error(assertion_error const&) = default;
    assertion_error& operator=(assertion_error const&) = default;

    char const* what() const noexcept override;

private:
    std::string _msg;
};

char const* assertion_error::what() const noexcept
{
    return _msg.c_str();
}

} // namespace _

// Override `CPPOSSL_ASSERT` to test `CPPOSSL_THROW_LAST_OPENSSL_ERROR` macro behavior
#undef CPPOSSL_ASSERT
#define CPPOSSL_ASSERT(expr, ...)            \
    do                                       \
    {                                        \
        if (!(expr))                         \
            throw _::assertion_error(#expr); \
    } while (0)

TEST_CASE("openssl_error")
{
    ossl::openssl_error error(1, "Test exception.");
    REQUIRE(error.what() == std::string("OpenSSL error: 1 - error:00000001:lib(0)::reason(1) - Test exception."));
}

TEST_CASE("openssl_error w/ debug")
{
    std::string const file = __FILE__;
    ossl::openssl_error error(1, "Test exception.", __LINE__, file.c_str());
    REQUIRE_THAT(error.what(), ContainsSubstring(file) && ContainsSubstring("on line"));
}

TEST_CASE("openssl_error copy")
{
    ossl::openssl_error const error_one(1, "Test error one.");
    ossl::openssl_error const error_two(2, "Test error two.");

    ossl::openssl_error copy(error_one);
    REQUIRE(copy.error() == error_one.error());

    copy = error_two;
    REQUIRE(copy.error() == error_two.error());
}

TEST_CASE("openssl_error move")
{
    ossl::openssl_error error_one(1, "Test error one.");
    ossl::openssl_error error_two(2, "Test error two.");

    ossl::openssl_error copy(std::move(error_one));
    REQUIRE(copy.error() == 1);

    copy = std::move(error_two);
    REQUIRE(copy.error() == 2);
}

TEST_CASE("openssl_error macro")
{
    ERR_clear_error();

    // Throwing with no error asserts
    REQUIRE_THROWS_AS([&]() { CPPOSSL_THROW_LAST_OPENSSL_ERROR("Test exception."); }(), _::assertion_error);

    // Invoke an openssl error
    ERR_raise(ERR_LIB_SYS, EINVAL);
    REQUIRE(ERR_peek_last_error() != 0);

    REQUIRE_THROWS_MATCHES([&]() { CPPOSSL_THROW_LAST_OPENSSL_ERROR("Test exception."); }(),
        ossl::openssl_error,
        MessageMatches(ContainsSubstring("Test exception.")));

    // Error is cleared afterwards
    REQUIRE_THROWS_AS([&]() { CPPOSSL_THROW_LAST_OPENSSL_ERROR("Test exception."); }(), _::assertion_error);
}
