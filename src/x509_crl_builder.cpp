//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/x509_crl_builder.hpp"
#include "cppossl/error.hpp"

namespace ossl {
namespace x509_crl {
    namespace builder {

        namespace _ {

            void set_lastupdate(rwref crl, asn1::time::roref lastupdate)
            {
                if (!X509_CRL_set1_lastUpdate(crl.get(), lastupdate.get()))
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 CRL last update property."); // LCOV_EXCL_LINE
            }

            void set_issuer(rwref crl, x509_name::roref name)
            {
                if (X509_CRL_set_issuer_name(crl.get(), name.get()) == 0)
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 CRL issuer."); // LCOV_EXCL_LINE
            }

        } // namespace _

        void set_lastupdate(context& ctx, asn1::time::roref lastupdate)
        {
            _::set_lastupdate(ctx.get(), lastupdate);
        }

        void set_nextupdate(context& ctx, asn1::time::roref nextupdate)
        {
            if (!X509_CRL_set1_nextUpdate(ctx.get(), nextupdate.get()))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 CRL next update property."); // LCOV_EXCL_LINE
        }

        void add(context& ctx, ossl::x509::roref cert, asn1::time::roref revocation_time)
        {
            add(ctx, cert, revocation_time, static_cast<uint8_t>(OCSP_REVOKED_STATUS_UNSPECIFIED));
        }

        void add(context& ctx, ossl::x509::roref cert, asn1::time::roref revocation_time, int reason)
        {
            auto tmp = make<asn1::ENUMERATED>();
            if (tmp == nullptr || !ASN1_ENUMERATED_set(tmp.get(), reason))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to created CRL revocation reason object."); // LCOV_EXCL_LINE
            add(ctx, cert, revocation_time, tmp.get());
        }

        void add(context& ctx,
            ossl::x509::roref cert,
            asn1::time::roref revocation_time,
            raii::roref<::ASN1_ENUMERATED> reason)
        {
            auto revoked = ossl::make<::X509_REVOKED>();

            if (!X509_REVOKED_set_serialNumber(revoked.get(), X509_get_serialNumber(const_cast<::X509*>(cert.get()))))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X509_REVOKED serial number."); // LCOV_EXCL_LINE

            if (!X509_REVOKED_set_revocationDate(revoked.get(), const_cast<::ASN1_TIME*>(revocation_time.get())))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X509_REVOKED revocation date."); // LCOV_EXCL_LINE

            if (X509_REVOKED_add1_ext_i2d(
                    revoked.get(), NID_crl_reason, const_cast<::ASN1_ENUMERATED*>(reason.get()), 0, 0)
                <= 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X509_REVOKED reason."); // LCOV_EXCL_LINE

            if (!X509_CRL_add0_revoked(ctx.get(), revoked.get()))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set revoked X.509 to X.509 CRL."); // LCOV_EXCL_LINE

            revoked.release();
        }

        ossl::owned<::X509_CRL> sign(
            ossl::x509::roref cert, ossl::evp_pkey::roref key, EVP_MD const* digest, std::function<void(context&)> func)
        {
            CPPOSSL_ASSERT(digest != nullptr);

            owned<::X509_CRL> crl = make<X509_CRL>();
            context ctx(crl);

            func(ctx);

            X509_CRL_sort(crl.get());

            _::set_issuer(crl, X509_get_subject_name(cert.get()));
            if (X509_CRL_sign(crl.get(), const_cast<::EVP_PKEY*>(key.get()), digest) <= 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to sign X.509 CRL."); // LCOV_EXCL_LINE

            return crl;
        }

    } // namespace builder
} // namespace x509_crl
} // namespace ossl
