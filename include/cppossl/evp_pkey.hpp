//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string>

#include <openssl/evp.h>

#include <cppossl/raii.hpp>

namespace ossl {
namespace evp_pkey {

    using roref = raii::roref<::EVP_PKEY>;

    /**
     * \defgroup evp_pkey OpenSSL EVP_PKEY
     */
    /**@{*/

    /** @brief Retrieve a new reference to the given private key object. */
    owned<::EVP_PKEY> retain(roref key);

    /** @brief Determine if two private key's are equal. */
    bool equal(roref lhs, roref rhs);

    /**@}*/

} // namespace evp_pkey
} // namespace ossl
