//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string>

#include <cppossl/bio.hpp>
#include <cppossl/raii.hpp>

namespace ossl {

/**
 * \defgroup x509_crl OpenSSL X509_CRL
 */
/**@{*/

/** @brief Retrieve a new reference to the given X.509 CRL object. */
x509_crl_t new_ref(x509_crl_t const& crl);

/** @brief Print X.509 CRL text to a string. */
std::string print_text(::X509_CRL const* crl);

/** @brief Print X.509 CRL text to a string. */
inline std::string print_text(x509_crl_t const& crl)
{
    return print_text(crl.get());
}

/** @brief Print X.509 CRL text to an OpenSSL BIO. */
void print_text(bio const& bio, ::X509_CRL const* crl);

/** @brief Print X.509 CRL text to an OpenSSL BIO. */
inline void print_text(bio const& bio, x509_crl_t const& crl)
{
    print_text(bio, crl.get());
}

/**@}*/

} // namespace ossl
