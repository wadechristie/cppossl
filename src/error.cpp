//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <array>

#include "cppossl/error.hpp"

namespace ossl {

openssl_error::openssl_error(int error, char const* msg)
    : _error(error)
{
    std::array<char, 256 + 1> ossl_error_str { 0 };
    std::array<char, 1024> error_str { 0 };
    char const* errmsg = ERR_error_string(error, ossl_error_str.data());
    snprintf(error_str.data(), error_str.size() - 1, "OpenSSL error: %d - %s - %s", error, errmsg, msg);
    _msg = std::string { error_str.data() };
}

char const* openssl_error::what() const noexcept
{
    return _msg.c_str();
}

} // namespace ossl
