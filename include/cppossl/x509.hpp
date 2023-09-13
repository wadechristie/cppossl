//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string>

#include <cppossl/bio.hpp>
#include <cppossl/raii.hpp>
#include <cppossl/x509_name.hpp>

namespace ossl {
namespace x509 {

    using roref = raii::roref<::X509>;
    using rwref = raii::rwref<::X509>;

    /**
     * \defgroup x509 OpenSSL X509
     */
    /**@{*/

    /** @brief Retrieve a new reference to the given X.509 object. */
    owned<::X509> retain(roref x509);

    /** @brief Determine if two X.509 objects are equal. */
    bool equal(roref lhs, roref rhs);

    /** @brief Return the X.509 parsed issuer principal. */
    owned<::X509_NAME> get_issuer(roref x509);

    /** @brief Return the X.509 parsed subject principal. */
    owned<::X509_NAME> get_subject(roref x509);

    /** @brief Get certificate notBefore timestamp. */
    time_t get_not_before(roref x509);

    /** @brief Get certificate notAfter timestamp. */
    time_t get_not_after(roref x509);

    ossl::owned<::ASN1_INTEGER> get_serial_number(roref x509);

    ossl::owned<::BIGNUM> get_serial_number_bn(roref x509);

    std::string get_serial_number_hex(roref x509);

    /** @brief Return true if the given private key matches the given X.509 certificate. */
    bool check_key(roref x509, raii::roref<::EVP_PKEY> pkey);

    /** @brief Print X.509 certificate text to a string. */
    std::string print_text(roref x509);

    /** @brief Print X.509 certificate text to an OpenSSL BIO. */
    void print_text(bio const& bio, roref x509);

    /**@}*/

} // namespace x509
} // namespace ossl
