//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <chrono>
#include <functional>
#include <string_view>
#include <vector>

#include <openssl/ocsp.h>

#include <cppossl/asn1_time.hpp>
#include <cppossl/evp_pkey.hpp>
#include <cppossl/x509.hpp>
#include <cppossl/x509_crl.hpp>
#include <cppossl/x509_name.hpp>

namespace ossl {
namespace x509_crl {

    /**
     * \defgroup x509_crl OpenSSL X509_CRL
     */
    /**@{*/

    /**
     * @brief X509_CRL object builder.
     */
    class builder
    {
    public:
        /**
         * @brief Construct a builder ready for building
         *
         * @throws ossl::openssl_error
         */
        inline builder()
        {
            reset();
        }

        builder(builder&&) noexcept = default;
        builder& operator=(builder&&) noexcept = default;

        builder(builder const&) noexcept = default;
        builder& operator=(builder const&) noexcept = default;

        ~builder() noexcept = default;

        builder& set_lastupdate(asn1_time::roref lastupdate);

        builder& set_nextupdate(asn1_time::roref nextupdate);

        builder& add(ossl::x509::roref cert, asn1_time::roref revocation_time);
        builder& add(ossl::x509::roref cert, asn1_time::roref revocation_time, int reason);
        builder& add(ossl::x509::roref cert, asn1_time::roref revocation_time, raii::roref<::ASN1_ENUMERATED> reason);

        /**
         * @brief Sign the current certificate revocation list context.
         *
         * @throws certify::openssl_error
         */
        ossl::owned<::X509_CRL> sign(ossl::x509::roref cert, ossl::evp_pkey::roref key, ::EVP_MD const* digest);

        /**
         * @brief Reset the builder back to initial state ready for building.
         *
         * @throws ossl::openssl_error
         */
        void reset();

    private:
        /**
         * @brief Set X.509 CRL issuer field.
         *
         * @throws certify::openssl_error
         */
        void set_issuer(x509_name::roref name);

        ossl::owned<::X509_CRL> _crl;
    };

    inline owned<::X509_CRL> sign(ossl::x509::roref signing_cert,
        ossl::evp_pkey::roref signing_key,
        ::EVP_MD const* digest,
        std::function<void(builder&)> callback)
    {
        builder b;
        callback(b);
        return b.sign(signing_cert, signing_key, digest);
    }

    /**@}*/

} // namespace x509_crl
} // namespace ossl
