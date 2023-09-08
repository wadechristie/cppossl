//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cppossl/raii.hpp>

namespace ossl {

/**
 * \defgroup stack OpenSSL Stack Helpers
 */
/**@{*/

/** @brief Push a distribution point object onto the stack. */
void push(dist_point_sk_t const& dpoints, dist_point_t dpoint);

/** @brief Push a general name object onto the stack. */
void push(general_name_sk_t const& names, general_name_t name);

/** @brief Push a X.509 extension object onto the stack. */
void push(x509_extension_sk_t const& exts, x509_extension_t name);

/** @brief Push a X.509 CRL object onto the stack. */
void push(x509_crl_sk_t const& crls, x509_crl_t crl);

/**@}*/

} // namespace ossl
