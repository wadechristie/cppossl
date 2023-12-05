//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string>

#include <cppossl/bio.hpp>
#include <cppossl/raii.hpp>

namespace ossl {
namespace x509_crl {

    /**
     * \defgroup x509_crl OpenSSL X509_CRL
     */
    /**@{*/

    /** @brief X509_CRL readonly reference.*/
    using roref = raii::roref<::X509_CRL>;

    /** @brief X509_CRL readwrite reference.*/
    using rwref = raii::rwref<::X509_CRL>;

    /** @brief Retrieve a new reference to the given X.509 CRL object. */
    owned<::X509_CRL> retain(roref crl);

    /** @brief Print X.509 CRL text to a string. */
    std::string print_text(roref crl);

    /** @brief Print X.509 CRL text to an OpenSSL BIO. */
    void print_text(bio const& bio, roref crl);

    /**@}*/

} // namespace x509_crl
} // namespace ossl
