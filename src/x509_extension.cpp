//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <sstream>

#include "cppossl/der.hpp"
#include "cppossl/object.hpp"
#include "cppossl/x509_extension.hpp"

namespace ossl {
namespace x509_extension {

    namespace _ {

        owned<::X509_EXTENSION> ext_from_conf(object::nid const& id, char const* str)
        {
            ossl::owned<::X509_EXTENSION> ext { X509V3_EXT_conf_nid(nullptr, nullptr, id, str) };
            if (ext == nullptr)
            {
                std::string msg = (std::stringstream()
                    << "Failed to create X.509 " << object::short_name(id) << " extension object.")
                                      .str();
                CPPOSSL_THROW_LAST_OPENSSL_ERROR(msg.c_str()); // LCOV_EXCL_LINE
            }
            return ext;
        }

    } // namespace _

    owned<::X509_EXTENSION> make_basic_constraints(bool ca, int pathlen)
    {
        std::stringstream ss;
        ss << (ca ? "critical, CA:TRUE" : "CA:FALSE");
        if (pathlen >= 0)
            ss << ", pathlen:" << pathlen;
        auto const str = ss.str();

        return make_basic_constraints(str.c_str());
    }

    owned<::X509_EXTENSION> make_basic_constraints(char const* confstr)
    {
        return _::ext_from_conf(object::wellknown_nid::basic_constraints, confstr);
    } // LCOV_EXCL_LINE

    owned<::X509_EXTENSION> make_key_usage(char const* confstr, bool critical)
    {
        ossl::owned<X509_EXTENSION> ext = _::ext_from_conf(object::wellknown_nid::key_usage, confstr);

        // TODO: remove
        if (critical)
        {
            if (!X509_EXTENSION_set_critical(ext.get(), 1))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                    "Failed to set X.509 keyUsage extension as critical.");
        }

        return ext;
    } // LCOV_EXCL_LINE

    owned<::X509_EXTENSION> make_ext_key_usage(char const* confstr, bool critical)
    {
        ossl::owned<X509_EXTENSION> ext = _::ext_from_conf(object::wellknown_nid::ext_key_usage, confstr);

        // TODO: remove
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

    owned<::X509_EXTENSION> make_authority_access_info(char const* confstr)
    {
        return _::ext_from_conf(object::wellknown_nid::info_access, confstr);
    } // LCOV_EXCL_LINE

} // namespace x509_extension
} // namespace ossl
