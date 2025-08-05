//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cppossl/asn1_integer.hpp>
#include <cppossl/raii.hpp>

namespace ossl {
namespace bignum {

    /**
     * \defgroup OpenSSL BIGNUM
     */
    /**@{*/

    /** @brief BIGNUM readonly reference.*/
    using roref = raii::roref<::BIGNUM>;

    /** @brief BIGNUM readwrite reference.*/
    using rwref = raii::rwref<::BIGNUM>;

    owned<::BIGNUM> make(uint64_t value);
    owned<::BIGNUM> make(asn1::integer::roref value);

    std::string to_dec_string(roref bn);
    std::string to_hex_string(roref bn);

    owned<::BIGNUM> random();

    /**@}*/

} // namespace bignum
} // namespace ossl
