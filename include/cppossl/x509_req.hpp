//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string>
#include <string_view>

#include <cppossl/bio.hpp>
#include <cppossl/raii.hpp>

namespace ossl {

/**
 * \defgroup x509_req OpenSSL X509_REQ
 */
/**@{*/

/** @brief Return the X.509 parsed subject principal. */
x509_name_t get_subject(::X509_REQ const* req);

/** @brief Return the X.509 parsed subject principal. */
inline x509_name_t get_subject(x509_req_t const& req)
{
    return get_subject(req.get());
}

/** @brief Return true if the given private key matches the given X.509 certificate request. */
bool check_key(::X509_REQ const* req, ::EVP_PKEY const* pkey);

/** @brief Return true if the given private key matches the given X.509 certificate request. */
inline bool check_key(x509_req_t const& req, evp_pkey_t const& pkey)
{
    return check_key(req.get(), pkey.get());
}

/** @brief Print X.509 certificate request text to a string. */
std::string print_text(::X509_REQ const* req);

/** @brief Print X.509 certificate request text to a string. */
inline std::string print_text(x509_req_t const& req)
{
    return print_text(req.get());
}

/** @brief Print X.509 certificate request text to an OpenSSL BIO. */
void print_text(bio const& bio, ::X509_REQ const* req);

/** @brief Print X.509 certificate request text to an OpenSSL BIO. */
inline void print_text(bio const& bio, x509_req_t const& req)
{
    print_text(bio, req.get());
}

/**@}*/

} // namespace ossl
