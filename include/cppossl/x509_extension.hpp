//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cppossl/raii.hpp>
#include <cppossl/x509.hpp>

namespace ossl {
namespace x509_extension {

    /**
     * @brief Create a X.509 basicConstraints extension object.
     *
     * The critical flag on the extension is automatically enabled if `ca` is `true`.
     *
     * @param[in] ca Boolean flag indicating a CA certificate.
     * @param[in, optional] pathlen How many CAs are allowed in the chain below current CA certificate.
     *
     * @throws ossl::openssl_error
     * @returns ossl::owned<::X509_EXTENSION>
     */
    owned<::X509_EXTENSION> make_basic_constraints(bool ca, int pathlen = -1);

    /**
     * @brief Create a X.509 basicConstraints extension object from OpenSSL configuration string.
     *
     * Example: `critical,CA:TRUE,pathlen:0`
     *
     * @see `https://docs.openssl.org/3.0/man5/x509v3_config/#basic-constraints`
     *
     * @param[in] confstr OpenSSL configuration string.
     *
     * @throws ossl::openssl_error
     * @returns ossl::owned<::X509_EXTENSION>
     */
    owned<::X509_EXTENSION> make_basic_constraints(char const* confstr);

    /**
     * @brief Create a X.509 keyUsage extension object from OpenSSL configuration string.
     *
     * Example: `digitalSignature, keyCertSign, cRLSign`
     *
     * @see `https://docs.openssl.org/3.0/man5/x509v3_config/#key-usage`
     *
     * @param[in] confstr OpenSSL configuration string.
     *
     * @throws ossl::openssl_error
     * @returns ossl::owned<::X509_EXTENSION>
     */
    owned<::X509_EXTENSION> make_key_usage(char const* confstr, bool critical = false);

    // owned<::X509_EXTENSION> make_key_usage(raii::roref<::ASN1_BIT_STRING> usage, bool critical);

    /**
     * @brief Create a X.509 extendedKeyUsage extension object from OpenSSL configuration string.
     *
     * Example: `clientAuth, serverAuth`
     *
     * @see `https://docs.openssl.org/3.0/man5/x509v3_config/#extended-key-usage`
     *
     * @param[in] confstr OpenSSL configuration string.
     *
     * @throws ossl::openssl_error
     * @returns ossl::owned<::X509_EXTENSION>
     */
    owned<::X509_EXTENSION> make_ext_key_usage(char const* confstr, bool critical = false);

    /**
     * @brief Create a X.509 subjectAltName extension object.
     *
     * @param[in] altnames OpenSSL stack of `::GENERAL_NAME` objects.
     *
     * @throws ossl::openssl_error
     * @returns ossl::owned<::X509_EXTENSION>
     */
    owned<::X509_EXTENSION> make_subject_alt_names(raii::roref<STACK_OF(GENERAL_NAME)> altnames);

    owned<::X509_EXTENSION> make_authority_key_id(ossl::x509::roref cacert);

    owned<::X509_EXTENSION> make_crl_distribution_point(raii::roref<STACK_OF(DIST_POINT)> crldists);

    owned<::X509_EXTENSION> make_authority_access_info(char const* accessinfo);

} // namespace x509_extension
} // namespace ossl
