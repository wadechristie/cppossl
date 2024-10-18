//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cassert>
#include <stdexcept>
#include <string>
#include <system_error>

#include <openssl/err.h>

#define CPPOSSL_THROW_ERRNO(__err__, __msg__) throw std::system_error(__err__, std::system_category(), __msg__)
#ifndef NDEBUG
#define CPPOSSL_THROW_LAST_OPENSSL_ERROR(__msg__)                     \
    do                                                                \
    {                                                                 \
        ossl::error_code const ec = ERR_peek_error();                 \
        CPPOSSL_ASSERT(ec != 0);                                      \
        ERR_clear_error();                                            \
        throw ::ossl::openssl_error(ec, __msg__, __LINE__, __FILE__); \
    } while (0)
#else
#define CPPOSSL_THROW_LAST_OPENSSL_ERROR(__msg__)     \
    do                                                \
    {                                                 \
        ossl::error_code const ec = ERR_peek_error(); \
        CPPOSSL_ASSERT(ec != 0);                      \
        ERR_clear_error();                            \
        throw ::ossl::openssl_error(ec, __msg__);     \
    } while (0)
#endif

/** @brief Abort. */
#define CPPOSSL_ABORT(...) assert(false)

/** @brief Assertion. */
#define CPPOSSL_ASSERT(expr, ...) \
    do                            \
    {                             \
        assert(expr);             \
    } while (0)

#ifndef NDEBUG
/** @brief Debug assertion. */
#define CPPOSSL_DASSERT(expr, ...) \
    do                             \
    {                              \
        assert(expr);              \
    } while (0)
#else
#define CPPOSSL_DASSERT(...)
#endif

namespace ossl {

using error_code = unsigned long;

/**
 * \defgroup error Exceptions
 */
/**@{*/

/** @brief OpenSSL exception type. */
class openssl_error : public std::exception
{
public:
    openssl_error(error_code error, char const* msg);
    openssl_error(error_code error, char const* msg, uint32_t line, char const* file);

    openssl_error(openssl_error&&) = default;
    openssl_error& operator=(openssl_error&&) = default;

    openssl_error(openssl_error const&) = default;
    openssl_error& operator=(openssl_error const&) = default;

    virtual ~openssl_error() = default;

    virtual char const* what() const noexcept override;

    inline error_code error() const noexcept
    {
        return _error;
    }

private:
    error_code _error { 0 };
    std::string _msg;
};

/**@}*/

} // namespace ossl
