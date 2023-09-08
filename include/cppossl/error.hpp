//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cassert>
#include <stdexcept>
#include <string>
#include <system_error>

#include <openssl/err.h>

#define CPPOSSL_THROW_ERRNO(err, msg) throw std::system_error(err, std::system_category(), msg)
#define CPPOSSL_THROW_LAST_OPENSSL_ERROR(msg) throw ::ossl::openssl_error(ERR_get_error(), msg)

/** @brief Abort. */
#define CPPOSSL_ABORT(...) assert(false)

/** @brief Assertion. */
#define CPPOSSL_ASSERT(expr, ...) \
    do {                          \
        assert(expr);             \
    } while (0)

#ifndef NDEBUG
/** @brief Debug assertion. */
#define CPPOSSL_DASSERT(expr, ...) \
    do {                           \
        assert(expr);              \
    } while (0)
#else
#define CPPOSSL_DASSERT(...)
#endif

namespace ossl {

/**
 * \defgroup error Exceptions
 */
/**@{*/

/** @brief OpenSSL exception type. */
class openssl_error : public std::exception {
public:
    openssl_error(int error, char const* msg);

    openssl_error(openssl_error&&) = default;
    openssl_error& operator=(openssl_error&&) = default;

    openssl_error(openssl_error const&) = default;
    openssl_error& operator=(openssl_error const&) = default;

    virtual ~openssl_error() = default;

    char const* what() const noexcept override;

    inline int error() const noexcept
    {
        return _error;
    }

private:
    int _error { -1 };
    std::string _msg;
};

/**@}*/

} // namespace ossl
