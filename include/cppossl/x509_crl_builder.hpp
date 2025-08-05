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

#include <cppossl/asn1_string.hpp>
#include <cppossl/asn1_time.hpp>
#include <cppossl/evp_pkey.hpp>
#include <cppossl/x509.hpp>
#include <cppossl/x509_crl.hpp>
#include <cppossl/x509_name.hpp>

namespace ossl {
namespace x509_crl {
    namespace builder {

        /**
         * \defgroup x509_crl OpenSSL X509_CRL
         */
        /**@{*/

        /**
         * @brief X509_CRL object builder context.
         */
        class context
        {
        public:
            context(context&&) = delete;
            context& operator=(context&&) = delete;

            context(context const&) = delete;
            context& operator=(context const&) = delete;

            ~context() = default;

            inline ::X509_CRL* get() const
            {
                return _crl.get();
            }

        private:
            inline context(owned<::X509_CRL>& crl)
                : _crl(crl)
            {
            }

            x509_crl::rwref _crl;

            friend ossl::owned<::X509_CRL> sign(ossl::x509::roref cert,
                ossl::evp_pkey::roref key,
                ::EVP_MD const* digest,
                std::function<void(context&)> func);
        };

        /**
         * @brief Sign the current certificate revocation list context.
         *
         * @throws certify::openssl_error
         */
        ossl::owned<::X509_CRL> sign(ossl::x509::roref cert,
            ossl::evp_pkey::roref key,
            ::EVP_MD const* digest,
            std::function<void(context&)> func);

        void set_lastupdate(context& ctx, asn1::time::roref lastupdate);

        void set_nextupdate(context& ctx, asn1::time::roref nextupdate);

        void add(context& ctx, ossl::x509::roref cert, asn1::time::roref revocation_time);
        void add(context& ctx, ossl::x509::roref cert, asn1::time::roref revocation_time, int reason);
        void add(context& ctx,
            ossl::x509::roref cert,
            asn1::time::roref revocation_time,
            raii::roref<::ASN1_ENUMERATED> reason);

        /**@}*/

    } // namespace builder
} // namespace x509_crl
} // namespace ossl
