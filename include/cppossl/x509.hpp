//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string>

#include <cppossl/bio.hpp>
#include <cppossl/raii.hpp>
#include <cppossl/x509_name.hpp>

namespace ossl {
namespace x509 {

    /**
     * \defgroup x509 OpenSSL X509
     */
    /**@{*/

    /** @brief X509 readonly reference.*/
    using roref = raii::roref<::X509>;

    /** @brief X509 readwrite reference.*/
    using rwref = raii::rwref<::X509>;

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

    /** @brief Get raw certificate serial number. */
    ossl::owned<::ASN1_INTEGER> get_serial_number(roref x509);

    /** @brief Get certificate serial number as BIGNUM. */
    ossl::owned<::BIGNUM> get_serial_number_bn(roref x509);

    /** @brief Get certificate serial number as a hex encoded string. */
    std::string get_serial_number_hex(roref x509);

    /** @brief Return true if the given private key matches the given X.509 certificate. */
    bool check_key(roref x509, raii::roref<::EVP_PKEY> pkey);

    /** @brief Print X.509 certificate text to a string. */
    std::string print_text(roref x509);

    std::string print_text(raii::roref<STACK_OF(X509)> stack);

    /** @brief Print X.509 certificate text to an OpenSSL BIO. */
    void print_text(bio const& bio, roref x509);

    /** @brief Print stack of X.509 certificates text to an OpenSSL BIO. */
    void print_text(bio const& bio, raii::roref<STACK_OF(X509)> stack);

    /**@}*/

} // namespace x509
} // namespace ossl
