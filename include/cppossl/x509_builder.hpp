//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <chrono>
#include <functional>
#include <initializer_list>
#include <string_view>

#include "cppossl/general_name.hpp"
#include <cppossl/asn1_time.hpp>
#include <cppossl/evp_pkey.hpp>
#include <cppossl/x509.hpp>
#include <cppossl/x509_name.hpp>
#include <cppossl/x509_req.hpp>

namespace ossl {
namespace x509 {

    /**
     * \defgroup x509 OpenSSL X509
     */
    /**@{*/

    /**
     * @brief X509_CRL object builder.
     */
    class builder
    {
    public:
        /**
         * @brief Construct an empty builder context ready for building.
         *
         * @throws ossl::openssl_error
         */
        inline builder()
        {
            reset();
        }

        /**
         * @brief Construct a builder context starting from an X509_REQ object.
         *
         * @throws ossl::openssl_error
         */
        builder(x509_req::roref req, bool copy_exts);

        builder(builder&&) noexcept = default;
        builder& operator=(builder&&) noexcept = default;

        builder(builder const&) noexcept = delete;
        builder& operator=(builder const&) noexcept = delete;

        ~builder() noexcept = default;

        /**
         * @brief Set X.509 serial number
         *
         * @throws ossl::openssl_error
         */
        builder& set_serialno(ossl::raii::roref<::BIGNUM> serial);

        /**
         * @brief Set a random X.509 serial number
         *
         * @throws ossl::openssl_error
         */
        builder& set_random_serialno();

        /**
         * @brief Set X.509 public key.
         *
         * @throws ossl::openssl_error
         */
        builder& set_public_key(ossl::evp_pkey::roref pubkey);

        /**
         * @brief Set X.509 subject field.
         *
         * @throws ossl::openssl_error
         */
        builder& set_subject(ossl::x509_name::roref name);

        /**
         * @brief Set X.509 notBefore field.
         *
         * @throws ossl::openssl_error
         */
        builder& set_not_before(asn1::time::roref not_before);

        /**
         * @brief Set X.509 notAfter field.
         *
         * @throws ossl::openssl_error
         */
        builder& set_not_after(asn1::time::roref not_after);

        /**
         * @brief Add the basicConstraints extension to the X.509 certificate.
         *
         * @param[in] ca set as `critical, CA:TRUE` if true, else `CA:FALSE`.
         * @param[in] pathlen set an optional pathlen to a nonnegative value.
         * @throws ossl::openssl_error
         */
        builder& set_basic_constraints_ext(bool ca, int pathlen = -1);

        /**
         * @brief Add the keyUsage extension to the X.509 certificate.
         *
         * @param[in] usage A set of usage flags.
         * @throws ossl::openssl_error
         */
        builder& set_key_usage_ext(std::string_view const& usagestr, bool critical = false);

        /**
         * @brief Add the extKeyUsage extension to the X.509 certificate.
         *
         * @param[in] ext_usage a set of ext usage flags.
         * @throws ossl::openssl_error
         */
        builder& set_ext_key_usage_ext(std::string_view const& usagestr, bool critical = false);

        /**
         * @brief Add the subjectAltNames extension to the X.509 certificate from the given stack of names.
         *
         * @throws ossl::openssl_error
         */
        builder& set_subject_alt_names_ext(owned<STACK_OF(GENERAL_NAME)> const& altnames);

        /**
         * @brief Add the subjectAltNames extension to the the X.509 certificate from the given vector of names.
         *
         * @throws ossl::openssl_error
         */
        builder& set_subject_alt_names_ext(std::initializer_list<owned<::GENERAL_NAME>> const& altnames);

        /**
         * @brief Add the subjectKeyIdentifier extension to the certificate.
         *
         * @throws ossl::openssl_error
         */
        builder& set_subject_key_id_ext();

        /**
         * @brief Add the authorityKeyIdentifier extension to the certificate.
         *
         * @throws ossl::openssl_error
         */
        builder& set_authority_key_id_ext(ossl::x509::roref cacert);

        /**
         * @brief Add the crlDistributionPoints extension to the X.509 certificate.
         *
         * @throws ossl::openssl_error
         */
        builder& set_crl_distribution_point_ext(raii::roref<STACK_OF(DIST_POINT)> crldists);

        /**
         * @brief Add the authorityInfoAccess extension to the X.509  certificate.
         *
         * @throws ossl::openssl_error
         */
        builder& set_authority_access_info_ext(std::string_view const& accessinfo);

        /**
         * @brief Sign a the current builder context.
         *
         * @param[in] issuer_cert the issuing certificate.
         * @param[in] issuer_key the issuing certificate key.
         * @param[in] digest digest to use for the signature. (Default=sha256)
         * @throws ossl::openssl_error
         */
        ossl::owned<::X509> sign(ossl::x509::roref issuer_cert, ossl::evp_pkey::roref issuer_key, EVP_MD const* digest);

        /**
         * @brief Selfsign a the current builder context.
         *
         * @param[in] key the certificate key.
         * @param[in] digest digest to use for the signature
         * @throws ossl::openssl_error
         */
        ossl::owned<::X509> selfsign(ossl::evp_pkey::roref key, EVP_MD const* digest);

        /**
         * @brief Reset the builder back to initial state ready for building.
         *
         * @throws ossl::openssl_error
         */
        owned<::X509> reset();

    protected:
        /**
         * @brief Set X.509 issuer field.
         *
         * @throws ossl::openssl_error
         */
        builder& set_issuer(ossl::x509_name::roref name);

        owned<::X509> _x509;
    };

    inline owned<::X509> selfsign(
        ossl::evp_pkey::roref key, EVP_MD const* digest, std::function<void(builder&)> callback)
    {
        builder b;
        callback(b);
        return b.selfsign(key, digest);
    }

    inline owned<::X509> sign(ossl::x509::roref signing_cert,
        ossl::evp_pkey::roref signing_key,
        EVP_MD const* digest,
        std::function<void(builder&)> callback)
    {
        builder b;
        callback(b);
        return b.sign(signing_cert, signing_key, digest);
    }

    /**@}*/

} // namespace x509
} // namespace ossl
