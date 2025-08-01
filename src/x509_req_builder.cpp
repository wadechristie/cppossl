//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/x509_req_builder.hpp"
#include "cppossl/bio.hpp"
#include "cppossl/error.hpp"
#include "cppossl/general_name.hpp"
#include "cppossl/stack.hpp"
#include "cppossl/x509_extension.hpp"

namespace ossl {
namespace x509_req {

    namespace _ {

        void add_extension(ossl::owned<STACK_OF(X509_EXTENSION)>& sk, ossl::owned<::X509_EXTENSION> ext)
        {
            if (sk == nullptr)
                sk = ossl::make<STACK_OF(X509_EXTENSION)>();

            // TODO filter the list for matching nids?

            sk::wrap(sk).push(std::move(ext));
        }

    } // namespace _

    void builder::reset()
    {
        auto req = make<::X509_REQ>();

        if (!X509_REQ_set_version(req.get(), X509_REQ_VERSION_1))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate request version."); // LCOV_EXCL_LINE

        _req = std::move(req);
    }

    builder& builder::set_subject(ossl::x509_name::roref name)
    {
        if (!X509_REQ_set_subject_name(_req.get(), name.get()))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate request subject."); // LCOV_EXCL_LINE
        return *this;
    }

    builder& builder::set_key_usage_ext(char const* usagestr, bool critical)
    {
        auto ext = x509_extension::make_key_usage(usagestr, critical);
        _::add_extension(_exts, std::move(ext));
        return *this;
    }

    builder& builder::set_ext_key_usage_ext(char const* usagestr, bool critical)
    {

        auto ext = x509_extension::make_ext_key_usage(usagestr, critical);
        _::add_extension(_exts, std::move(ext));
        return *this;
    }

    builder& builder::set_subject_alt_names_ext(owned<STACK_OF(GENERAL_NAME)> const& altnames)
    {
        auto ext = x509_extension::make_subject_alt_names(altnames);
        _::add_extension(_exts, std::move(ext));
        return *this;
    }

    builder& builder::set_subject_alt_names_ext(std::initializer_list<owned<::GENERAL_NAME>> const& altnames)
    {
        auto gnames = sk::make<GENERAL_NAME>();
        for (auto const& name : altnames)
            gnames.push(general_name::copy(name));

        return set_subject_alt_names_ext(gnames.mine());
    }

    owned<::X509_REQ> builder::sign(ossl::evp_pkey::roref key, EVP_MD const* digest)
    {
        CPPOSSL_ASSERT(digest != nullptr);

        if (_exts != nullptr)
        {
            if (!X509_REQ_add_extensions(_req.get(), _exts.get()))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                    "Failed to set X.509 certificate request extensions.");
        }

        if (!X509_REQ_set_pubkey(_req.get(), const_cast<::EVP_PKEY*>(key.get())))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate request public key."); // LCOV_EXCL_LINE

        if (X509_REQ_sign(_req.get(), const_cast<::EVP_PKEY*>(key.get()), digest) <= 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to sign X.509 certificate request."); // LCOV_EXCL_LINE

        auto req = std::move(_req);
        reset();
        return req;
    } // LCOV_EXCL_LINE

} // namespace x509_req
} // namespace ossl
