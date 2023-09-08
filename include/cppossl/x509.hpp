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
 * \defgroup x509 OpenSSL X509
 */
/**@{*/

/** @brief Retrieve a new reference to the given X.509 object. */
x509_t new_ref(x509_t const& x509);

/** @brief Determine if two X.509 objects are equal. */
bool equal(x509_t const& lhs, x509_t const& rhs);

/** @brief Return the X.509 parsed issuer principal. */
x509_name_t get_issuer(::X509 const* x509);

/** @brief Return the X.509 parsed issuer principal. */
inline x509_name_t get_issuer(x509_t const& x509)
{
    return get_issuer(x509.get());
}

/** @brief Return the X.509 parsed subject principal. */
x509_name_t get_subject(::X509 const* x509);

/** @brief Return the X.509 parsed subject principal. */
inline x509_name_t get_subject(x509_t const& x509)
{
    return get_subject(x509.get());
}

/** @brief Get certificate notBefore timestamp. */
time_t get_not_before(::X509 const* x509);

/** @brief Get certificate notBefore timestamp. */
inline time_t get_not_before(x509_t const& x509)
{
    return get_not_before(x509.get());
}

/** @brief Get certificate notAfter timestamp. */
time_t get_not_after(::X509 const* x509);

/** @brief Get certificate notAfter timestamp. */
inline time_t get_not_after(x509_t const& x509)
{
    return get_not_after(x509.get());
}

std::string get_serial_number_hex(::X509 const* x509);

inline std::string get_serial_number_hex(x509_t const& x509)
{
    return get_serial_number_hex(x509.get());
}

/** @brief Return true if the given private key matches the given X.509 certificate. */
bool check_key(::X509 const* x509, ::EVP_PKEY const* pkey);

/** @brief Return true if the given private key matches the given X.509 certificate. */
inline bool check_key(x509_t const& x509, ossl::evp_pkey_t const& pkey)
{
    return check_key(x509.get(), pkey.get());
}

/** @brief Print X.509 certificate text to a string. */
std::string print_text(::X509 const* x509);

/** @brief Print X.509 certificate text to a string. */
inline std::string print_text(x509_t const& x509)
{
    return print_text(x509.get());
}

/** @brief Print X.509 certificate text to an OpenSSL BIO. */
void print_text(bio const& bio, ::X509 const* x509);

/** @brief Print X.509 certificate text to an OpenSSL BIO. */
inline void print_text(bio const& bio, x509_t const& x509)
{
    print_text(bio, x509.get());
}

/**@}*/

} // namespace ossl
