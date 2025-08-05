//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <functional>
#include <initializer_list>
#include <string_view>

#include <cppossl/evp_pkey.hpp>
#include <cppossl/x509_name.hpp>
#include <cppossl/x509_req.hpp>
#include <cppossl/x509_subject_alt_name.hpp>

namespace ossl {
namespace x509_req {
    namespace builder {

        /**
         * \defgroup x509_req OpenSSL X509_REQ
         */
        /**@{*/

        /**
         * @brief X509_REQ builder context.
         */
        class context
        {
        public:
            context(context&&) = delete;
            context& operator=(context&&) = delete;

            context(context const&) = delete;
            context& operator=(context const&) = delete;

            ~context() = default;

            inline ::X509_REQ* get() const
            {
                return _req.get();
            }

        private:
            inline context(owned<::X509_REQ>& req)
                : _req(req)
            {
            }

            /** @brief X.509 certificate request object being built. */
            x509_req::rwref _req;

            /** @brief Lazy initialized stack of X.509 extensions to add to the request during signing. */
            ossl::owned<STACK_OF(X509_EXTENSION)> _exts;

            friend owned<::X509_REQ> sign(
                ossl::evp_pkey::roref key, EVP_MD const* digest, std::function<void(context&)> func);
            friend void add_extension(context& ctx, ossl::owned<::X509_EXTENSION> ext);
        };

        /**
         * @brief Sign the current certificate request context.
         *
         * @throws ossl::openssl_error
         */
        owned<::X509_REQ> sign(ossl::evp_pkey::roref key, EVP_MD const* digest, std::function<void(context&)> func);

        void add_extension(context& ctx, ossl::owned<::X509_EXTENSION> ext);

        /**
         * @brief Set X.509 certificate request subject field.
         *
         * @throws ossl::openssl_error
         */
        void set_subject(context& ctx, ossl::x509_name::roref name);

        /**
         * @brief Add the keyUsage extension to the X.509 certificate.
         *
         * @param[in] usage A set of usage flags.
         * @throws ossl::openssl_error
         */
        void set_key_usage(context& ctx, char const* usagestr, bool critical = false);

        /**
         * @brief Add the extKeyUsage extension to the X.509 certificate.
         *
         * @param[in] ext_usage a set of ext usage flags.
         * @throws ossl::openssl_error
         */
        void set_ext_key_usage(context& ctx, char const* usagestr, bool critical = false);

        /**
         * @brief Add the subjectAltNames extension to the X.509 certificate request from the given stack of names.
         *
         * @throws ossl::openssl_error
         */
        void set_subject_alt_names(context& ctx, owned<STACK_OF(GENERAL_NAME)> const& altnames);

        /**
         * @brief Add the subjectAltNames extension to the X.509 certificate request from the given a list of names.
         *
         * @throws ossl::openssl_error
         */
        void set_subject_alt_names(context& ctx, std::initializer_list<x509::saltname> const& altnames);
        void set_subject_alt_names(context& ctx, std::vector<x509::saltname> const& altnames);

        /**@}*/

    } // builder
} // namespace x509_req
} // namespace ossl
