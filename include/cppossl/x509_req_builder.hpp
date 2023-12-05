//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <functional>
#include <initializer_list>
#include <string_view>

#include "cppossl/general_name.hpp"
#include <cppossl/evp_pkey.hpp>
#include <cppossl/x509_name.hpp>
#include <cppossl/x509_req.hpp>

namespace ossl {
namespace x509_req {

    /**
     * \defgroup x509_req OpenSSL X509_REQ
     */
    /**@{*/

    /**
     * @brief X509_REQ object builder.
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

        /**
         * @brief Set X.509 certificate request subject field.
         *
         * @throws ossl::openssl_error
         */
        builder& set_subject(ossl::x509_name::roref name);

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
         * @brief Add the subjectAltNames extension to the X.509 certificate request from the given stack of names.
         *
         * @throws ossl::openssl_error
         */
        builder& set_subject_alt_names_ext(owned<STACK_OF(GENERAL_NAME)> const& altnames);

        /**
         * @brief Add the subjectAltNames extension to the X.509 certificate request from the given a list of names.
         *
         * @throws ossl::openssl_error
         */
        builder& set_subject_alt_names_ext(std::initializer_list<owned<::GENERAL_NAME>> const& altnames);

        /**
         * @brief Sign the current certificate request context.
         *
         * @throws ossl::openssl_error
         */
        owned<::X509_REQ> sign(ossl::evp_pkey::roref key, EVP_MD const* digest);

        /**
         * @brief Reset the builder back to initial state ready for building.
         *
         * @throws ossl::openssl_error
         */
        void reset();

    private:
        /** @brief X.509 certificate request object being built. */
        owned<::X509_REQ> _req;

        /** @brief Lazy initialized stack of X.509 extensions to add to the request during signing. */
        ossl::owned<STACK_OF(X509_EXTENSION)> _exts;
    };

    inline owned<::X509_REQ> sign(
        ossl::evp_pkey::roref key, EVP_MD const* digest, std::function<void(builder&)> callback)
    {
        builder b;
        callback(b);
        return b.sign(key, digest);
    }

    /**@}*/

} // namespace x509_req
} // namespace ossl
