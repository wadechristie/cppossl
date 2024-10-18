//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/builder/x509_builder.hpp"
#include "cppossl/error.hpp"

namespace ossl {
namespace x509 {
    namespace v2 {
        namespace builder {

            namespace _ {

                /** @brief Remove all extensions matching `nid` from `cert`. */
                void remove_ext_by_nid(rwref x509, int const nid)
                {
                    for (int idx = -1; (idx = X509_get_ext_by_NID(x509.get(), nid, -1)) >= 0; idx = -1)
                    {
                        X509_EXTENSION* ext = X509_delete_ext(x509.get(), idx);
                        X509_EXTENSION_free(ext);
                    }
                }

                void add_extension(rwref x509, raii::roref<::X509_EXTENSION> ext)
                {
                    ASN1_OBJECT* obj = X509_EXTENSION_get_object(const_cast<::X509_EXTENSION*>(ext.get()));
                    remove_ext_by_nid(x509, OBJ_obj2nid(obj));
                    if (X509_add_ext(x509.get(), const_cast<::X509_EXTENSION*>(ext.get()), -1) < 0)
                        CPPOSSL_THROW_LAST_OPENSSL_ERROR(
                            "Failed to add new extension to X.509 object."); // LCOV_EXCL_LINE
                }

            } // namespace _

            ossl::owned<::X509> sign(ossl::x509::roref issuer_cert,
                ossl::evp_pkey::roref issuer_key,
                EVP_MD const* digest,
                std::function<void(context&)> func)
            {
                CPPOSSL_ASSERT(digest != nullptr);

                auto cert = make<::X509>();
                context ctx(cert);

                // execute caller callback
                func(ctx);

                owned<::EVP_PKEY> const pubkey { X509_get_pubkey(cert.get()) };
                if (pubkey == nullptr)
                    CPPOSSL_THROW_ERRNO(EINVAL, "X.509 public key was not set"); // LCOV_EXCL_LINE

                set_issuer(ctx, X509_get_subject_name(issuer_cert.get()));

                if (X509_sign(cert.get(), const_cast<::EVP_PKEY*>(issuer_key.get()), digest) <= 0)
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to sign X.509 certificate."); // LCOV_EXCL_LINE

                return cert;
            }

            owned<::X509> selfsign(ossl::evp_pkey::roref key, EVP_MD const* digest, std::function<void(context&)> func)
            {
                CPPOSSL_ASSERT(digest != nullptr);

                auto cert = make<::X509>();
                context ctx(cert);

                // default to a random serial number
                set_random_serialno(ctx);

                // default notBefore & notAfter to now
                auto const now = asn1::time::now();
                set_not_before(ctx, now);
                set_not_after(ctx, now);

                // execute caller callback
                func(ctx);

                // verify public key is set correctly
                owned<::EVP_PKEY> const pubkey { X509_get_pubkey(cert.get()) };
                if (pubkey == nullptr)
                {
                    set_public_key(ctx, key);
                }
                else
                {
                    if (!evp_pkey::equal(pubkey, key))
                        CPPOSSL_THROW_ERRNO(EINVAL, "X.509 public key was set but it does not match signing key.");
                }

                // set issuer equal to subject
                set_issuer(ctx, X509_get_subject_name(cert.get()));

                // sign
                if (X509_sign(cert.get(), const_cast<::EVP_PKEY*>(key.get()), digest) <= 0)
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to sign X.509 certificate."); // LCOV_EXCL_LINE

                // verify
                if (!ossl::x509::check_key(cert.get(), key))
                    throw std::runtime_error("Failed to verify X.509 the self-signed certificate."); // LCOV_EXCL_LINE

                return cert;
            }

            void set_serialno(context& ctx, ossl::raii::roref<::BIGNUM> serial)
            {
                if (BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(ctx.get())) == 0)
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                        "Failed to convert BIGNUM serial number to OpenSSL ASN1_INTEGER."); // LCOV_EXCL_LINE
            }

            void set_random_serialno(context& ctx)
            {
                auto randomserial = ossl::make<BIGNUM>();
                if (BN_rand(randomserial.get(), 64, 0, 0) == 0)
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to generate a random serial number."); // LCOV_EXCL_LINE

                set_serialno(ctx, randomserial);
            }

            void set_public_key(context& ctx, ossl::evp_pkey::roref pubkey)
            {
                if (!X509_set_pubkey(ctx.get(), const_cast<::EVP_PKEY*>(pubkey.get())))
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate public key."); // LCOV_EXCL_LINE
            }

            void set_subject(context& ctx, ossl::x509_name::roref name)
            {
                if (!X509_set_subject_name(ctx.get(), name.get()))
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate subject."); // LCOV_EXCL_LINE
            }

            void set_issuer(context& ctx, ossl::x509_name::roref name)
            {
                if (!X509_set_issuer_name(ctx.get(), name.get()))
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate issuer."); // LCOV_EXCL_LINE
            }

            void set_not_before(context& ctx, asn1::time::roref not_before)
            {
                if (!X509_set1_notBefore(ctx.get(), not_before.get()))
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate notBefore."); // LCOV_EXCL_LINE
            }

            void set_not_after(context& ctx, asn1::time::roref not_after)
            {
                if (!X509_set1_notAfter(ctx.get(), not_after.get()))
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate notAfter."); // LCOV_EXCL_LINE
            }

            void add_extension(context& ctx, owned<::X509_EXTENSION> ext)
            {
                _::add_extension(x509::rwref(ctx.get()), std::move(ext));
            }

        } // namespace builder
    } // namespace v2
} // namespace x509
} // namespace ossl
