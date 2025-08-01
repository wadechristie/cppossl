//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <functional>

#include <cppossl/asn1_time.hpp>
#include <cppossl/evp_pkey.hpp>
#include <cppossl/general_name.hpp>
#include <cppossl/object.hpp>
#include <cppossl/raii.hpp>
#include <cppossl/stack.hpp>
#include <cppossl/x509.hpp>
#include <cppossl/x509_extension.hpp>
#include <cppossl/x509_name.hpp>
#include <cppossl/x509_req.hpp>

namespace ossl {
namespace x509 {
    namespace v2 {

        namespace builder {

            class copy_extensions
            {
            public:
                inline static copy_extensions none()
                {
                    return copy_extensions {};
                };

                inline static copy_extensions all()
                {
                    static copy_extensions singleton;
                    return singleton;
                };

                inline copy_extensions(std::initializer_list<object::nid> nids)
                    : _nids(nids)
                {
                }

                ~copy_extensions() = default;

            private:
                copy_extensions() = default;

                std::vector<object::nid> _nids;
            };

            class context
            {
            public:
                context() = delete;

                context(context&&) = delete;
                context& operator=(context&&) = delete;

                context(context const&) = delete;
                context& operator=(context const&) = delete;

                ~context() = default;

                inline ::X509* get() const
                {
                    return _x509.get();
                }

            private:
                inline context(owned<::X509>& cert)
                    : _x509(cert)
                {
                }

                friend ossl::owned<::X509> sign(ossl::x509::roref issuer_cert,
                    ossl::evp_pkey::roref issuer_key,
                    EVP_MD const* digest,
                    std::function<void(context&)> func);

                friend owned<::X509> selfsign(
                    ossl::evp_pkey::roref key, EVP_MD const* digest, std::function<void(context&)> func);

                x509::rwref _x509;
            };

            ossl::owned<::X509> sign(ossl::x509::roref issuer_cert,
                ossl::evp_pkey::roref issuer_key,
                EVP_MD const* digest,
                std::function<void(context&)> func);

            owned<::X509> selfsign(ossl::evp_pkey::roref key, EVP_MD const* digest, std::function<void(context&)> func);

            void starting_from(context& ctx, ossl::x509_req::roref req);

            /**
             * @brief Set X.509 serial number
             *
             * @throws ossl::openssl_error
             */
            void set_serialno(context& ctx, ossl::raii::roref<::BIGNUM> serial);

            /**
             * @brief Set a random X.509 serial number
             *
             * @throws ossl::openssl_error
             */
            void set_random_serialno(context& ctx);

            /**
             * @brief Set X.509 public key.
             *
             * @throws ossl::openssl_error
             */
            void set_public_key(context& ctx, ossl::evp_pkey::roref pubkey);

            /**
             * @brief Set X.509 subject field.
             *
             * @throws ossl::openssl_error
             */
            void set_subject(context& ctx, ossl::x509_name::roref name);

            /**
             * @brief Set X.509 notBefore field.
             *
             * @throws ossl::openssl_error
             */
            void set_not_before(context& ctx, asn1::time::roref not_before);

            /**
             * @brief Set X.509 notAfter field.
             *
             * @throws ossl::openssl_error
             */
            void set_not_after(context& ctx, asn1::time::roref not_after);

            void add_extension(context& ctx, owned<::X509_EXTENSION> ext);

            template <size_t N>
            void add_extensions(context& ctx, std::array<owned<::X509_EXTENSION>, N> exts)
            {
                for (auto& etx : exts)
                    add_extension(ctx, std::move(etx));
            }

            /**
             * @brief Add the basicConstraints extension to the X.509 certificate.
             *
             * @param[in] ca set as `critical, CA:TRUE` if true, else `CA:FALSE`.
             * @param[in] pathlen set an optional pathlen to a nonnegative value.
             * @throws ossl::openssl_error
             */
            inline void set_basic_constraints(context& ctx, bool ca, int pathlen = -1)
            {
                auto ext = x509_extension::make_basic_constraints(ca, pathlen);
                add_extension(ctx, std::move(ext));
            }

            /**
             * @brief Add the keyUsage extension to the X.509 certificate.
             *
             * @see `https://docs.openssl.org/3.0/man5/x509v3_config/#key-usage`
             *
             * @param[in] confstr OpenSSL keyUsage configuration string.
             * @throws ossl::openssl_error
             */
            inline void set_key_usage(context& ctx, char const* confstr)
            {
                auto ext = x509_extension::make_key_usage(confstr);
                add_extension(ctx, std::move(ext));
            }

            /**
             * @brief Add the extendedKeyUsage extension to the X.509 certificate.
             *
             * @see `https://docs.openssl.org/3.0/man5/x509v3_config/#extended-key-usage`
             *
             * @param[in] confstr OpenSSL extendedKeyUsage configuration string.
             * @throws ossl::openssl_error
             */
            inline void set_ext_key_usage(context& ctx, char const* confstr)
            {
                auto ext = x509_extension::make_ext_key_usage(confstr);
                add_extension(ctx, std::move(ext));
            }

            /**
             * @brief Add the subjectAltNames extension to the X.509 certificate from the given stack of names.
             *
             * @throws ossl::openssl_error
             */
            void set_subject_alt_names(context& ctx, owned<STACK_OF(GENERAL_NAME)> const& altnames);

            /**
             * @brief Add the subjectKeyIdentifier extension to the certificate.
             *
             * `set_public_key()` should be called prior this function.
             *
             * @throws ossl::openssl_error
             */
            void set_subject_key_id(context& ctx);

            /**
             * @brief Add the authorityKeyIdentifier extension to the certificate.
             *
             * @throws ossl::openssl_error
             */
            inline void set_authority_key_id(context& ctx, x509::roref cacert)
            {
                auto ext = x509_extension::make_authority_key_id(cacert);
                add_extension(ctx, std::move(ext));
            }

            /**
             * @brief Add the crlDistributionPoints extension to the X.509 certificate.
             *
             * @throws ossl::openssl_error
             */
            inline void set_crl_distribution_point(context& ctx, raii::roref<STACK_OF(DIST_POINT)> crldists)
            {
                auto ext = x509_extension::make_crl_distribution_point(crldists);
                add_extension(ctx, std::move(ext));
            }

            /**
             * @brief Add the authorityInfoAccess extension to the X.509  certificate.
             *
             * @see `https://docs.openssl.org/3.0/man5/x509v3_config/#authority-info-access`
             *
             * @param[in] confstr OpenSSL authorityInfoAccess configuration string.
             * @throws ossl::openssl_error
             */
            inline void set_authority_access_info(context& ctx, char const* confstr)
            {
                auto ext = x509_extension::make_authority_access_info(confstr);
                add_extension(ctx, std::move(ext));
            }

        } // namespace v2
    } // namespace builder
} // namespace x509
} // namespace ossl
