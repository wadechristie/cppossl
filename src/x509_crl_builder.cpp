//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/x509_crl_builder.hpp"
#include "cppossl/error.hpp"

namespace ossl {
namespace x509_crl {

    namespace _ {

        void set_lastupdate(rwref crl, asn1_time::roref lastupdate)
        {
            if (!X509_CRL_set1_lastUpdate(crl.get(), lastupdate.get()))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 CRL last update property."); // LCOV_EXCL_LINE
        }

    } // namespace _

    void builder::reset()
    {
        auto crl = make<::X509_CRL>();
        X509_CRL_set_version(_crl.get(), X509_CRL_VERSION_2);
        _::set_lastupdate(crl, asn1_time::now());
        _crl = std::move(crl);
    }

    builder& builder::set_lastupdate(asn1_time::roref lastupdate)
    {
        _::set_lastupdate(_crl, lastupdate);
        return *this;
    }

    builder& builder::set_nextupdate(asn1_time::roref nextupdate)
    {
        if (!X509_CRL_set1_nextUpdate(_crl.get(), nextupdate.get()))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 CRL next update property."); // LCOV_EXCL_LINE

        return *this;
    }

    builder& builder::add(
        ossl::x509::roref cert, asn1_time::roref revocation_time, raii::roref<::ASN1_ENUMERATED> reason)
    {
        auto revoked = ossl::make<::X509_REVOKED>();

        if (!X509_REVOKED_set_serialNumber(revoked.get(), X509_get_serialNumber(const_cast<::X509*>(cert.get()))))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X509_REVOKED serial number."); // LCOV_EXCL_LINE

        if (!X509_REVOKED_set_revocationDate(revoked.get(), const_cast<::ASN1_TIME*>(revocation_time.get())))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X509_REVOKED revocation date."); // LCOV_EXCL_LINE

        if (X509_REVOKED_add1_ext_i2d(revoked.get(), NID_crl_reason, const_cast<::ASN1_ENUMERATED*>(reason.get()), 0, 0)
            <= 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X509_REVOKED reason."); // LCOV_EXCL_LINE

        if (!X509_CRL_add0_revoked(_crl.get(), revoked.get()))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set revoked X.509 to X.509 CRL."); // LCOV_EXCL_LINE

        revoked.release();
        return *this;
    }

    void builder::set_issuer(x509_name::roref name)
    {
        if (X509_CRL_set_issuer_name(_crl.get(), name.get()) == 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 CRL issuer."); // LCOV_EXCL_LINE
    }

    ossl::owned<::X509_CRL> builder::sign(ossl::x509::roref cert, ossl::evp_pkey::roref key, EVP_MD const* digest)
    {
        CPPOSSL_ASSERT(digest != nullptr);

        X509_CRL_sort(_crl.get());

        set_issuer(X509_get_subject_name(cert.get()));
        if (X509_CRL_sign(_crl.get(), const_cast<::EVP_PKEY*>(key.get()), digest) <= 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to sign X.509 CRL."); // LCOV_EXCL_LINE

        return std::move(_crl);
    }

} // namespace x509_crl
} // namespace ossl
