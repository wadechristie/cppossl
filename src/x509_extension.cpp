//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <sstream>

#include "cppossl/der.hpp"
#include "cppossl/x509_extension.hpp"

namespace ossl {
namespace x509_extension {

    owned<::X509_EXTENSION> make_basic_constraints(bool ca, int pathlen)
    {
        std::stringstream ss;
        ss << (ca ? "critical, CA:TRUE" : "CA:FALSE");
        if (pathlen >= 0)
            ss << ", pathlen:" << pathlen;
        auto const str = ss.str();

        return make_basic_constraints(str);
    }

    owned<::X509_EXTENSION> make_basic_constraints(std::string_view const& confstr)
    {
        ossl::owned<::X509_EXTENSION> ext { X509V3_EXT_conf_nid(
            nullptr, nullptr, NID_basic_constraints, confstr.data()) };
        if (ext == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to create X.509 basicConstraints extension object.");

        return ext;
    } // LCOV_EXCL_LINE

    owned<::X509_EXTENSION> make_key_usage(std::string_view const& usagestr, bool critical)
    {
        ossl::owned<X509_EXTENSION> ext { X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage, usagestr.data()) };
        if (ext == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to create X.509 keyUsage extension object.");

        if (critical)
        {
            if (!X509_EXTENSION_set_critical(ext.get(), 1))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                    "Failed to set X.509 keyUsage extension as critical.");
        }

        return ext;
    } // LCOV_EXCL_LINE

    owned<::X509_EXTENSION> make_key_usage(raii::roref<::ASN1_BIT_STRING> usage, bool critical)
    {
        raii::owned<::ASN1_OCTET_STRING> data = der::encode(usage).to_octet_string();
        ossl::owned<X509_EXTENSION> ext { X509_EXTENSION_create_by_NID(nullptr, NID_key_usage, critical, data.get()) };
        assert(ext);
        if (ext == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to create X.509 keyUsage extension object.");

        return ext;
    } // LCOV_EXCL_LINE

    owned<::X509_EXTENSION> make_ext_key_usage(std::string_view const& usagestr, bool critical)
    {
        ossl::owned<::X509_EXTENSION> ext { X509V3_EXT_conf_nid(nullptr, nullptr, NID_ext_key_usage, usagestr.data()) };
        if (ext == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to create X.509 extKeyUsage extension object.");

        if (critical)
        {
            if (!X509_EXTENSION_set_critical(ext.get(), 1))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                    "Failed to set X.509 extKeyUsage extension as critical.");
        }

        return ext;
    } // LCOV_EXCL_LINE

    owned<::X509_EXTENSION> make_subject_alt_names(raii::roref<STACK_OF(GENERAL_NAME)> altnames)
    {
        ossl::owned<::X509_EXTENSION> ext { X509V3_EXT_i2d(
            NID_subject_alt_name, /*crit=*/0, const_cast<STACK_OF(GENERAL_NAME)*>(altnames.get())) };
        if (ext == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to create X.509 subjectAltName extension object.");

        return ext;
    } // LCOV_EXCL_LINE

    owned<::X509_EXTENSION> make_authority_key_id(ossl::x509::roref cacert)
    {
        X509V3_CTX ctx {};
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, const_cast<::X509*>(cacert.get()), nullptr, nullptr, nullptr, 0);

        char const* value = "keyid:always";
        ossl::owned<::X509_EXTENSION> ext { X509V3_EXT_conf_nid(
            nullptr, &ctx, NID_authority_key_identifier, const_cast<char*>(value)) };
        if (ext == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to create X.509 authorityKeyIdentifier extension object.");

        return ext;
    } // LCOV_EXCL_LINE

    owned<::X509_EXTENSION> make_crl_distribution_point(raii::roref<STACK_OF(DIST_POINT)> crldists)
    {
        ossl::owned<::X509_EXTENSION> ext { X509V3_EXT_i2d(NID_crl_distribution_points,
            /*crit=*/0,
            const_cast<STACK_OF(DIST_POINT)*>(crldists.get())) };
        if (ext == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to create X.509 crlDistributionPoints extension to X.509 object.");

        return ext;
    } // LCOV_EXCL_LINE

    owned<::X509_EXTENSION> make_authority_access_info(std::string_view const& accessinfo)
    {
        ossl::owned<::X509_EXTENSION> ext { X509V3_EXT_conf_nid(nullptr, nullptr, NID_info_access, accessinfo.data()) };
        if (ext == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to create X.509 authorityAccessInfo extension object.");

        return ext;
    } // LCOV_EXCL_LINE

} // namespace x509_extension
} // namespace ossl
