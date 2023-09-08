//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string>

#include <cppossl/raii.hpp>

namespace ossl {

/**
 * \defgroup evp_pkey OpenSSL EVP_PKEY
 */
/**@{*/

/** @brief Retrieve a new reference to the given private key object. */
evp_pkey_t new_ref(evp_pkey_t const& key);

/** @brief Determine if two private key's are equal. */
bool equal(evp_pkey_t const& lhs, evp_pkey_t const& rhs);

/**@}*/

} // namespace ossl
