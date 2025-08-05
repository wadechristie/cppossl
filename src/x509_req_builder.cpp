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
    namespace builder {

        namespace _ {

        } // namespace _

        owned<::X509_REQ> sign(ossl::evp_pkey::roref key, EVP_MD const* digest, std::function<void(context&)> func)
        {
            owned<::X509_REQ> req = make<::X509_REQ>();
            context ctx(req);

            func(ctx);

            if (ctx._exts != nullptr)
            {
                if (!X509_REQ_add_extensions(req.get(), ctx._exts.get()))
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                        "Failed to set X.509 certificate request extensions.");
            }

            if (!X509_REQ_set_pubkey(req.get(), const_cast<::EVP_PKEY*>(key.get())))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR(
                    "Failed to set X.509 certificate request public key."); // LCOV_EXCL_LINE

            if (X509_REQ_sign(req.get(), const_cast<::EVP_PKEY*>(key.get()), digest) <= 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to sign X.509 certificate request."); // LCOV_EXCL_LINE

            return req;
        }

        void add_extension(context& ctx, ossl::owned<::X509_EXTENSION> ext)
        {
            if (ctx._exts == nullptr)
                ctx._exts = ossl::make<STACK_OF(X509_EXTENSION)>();

            // TODO filter the list for matching nids?

            sk::wrap(ctx._exts).push(std::move(ext));
        }

        void set_subject(context& ctx, ossl::x509_name::roref name)
        {
            if (!X509_REQ_set_subject_name(ctx.get(), name.get()))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate request subject."); // LCOV_EXCL_LINE
        }

        void set_key_usage(context& ctx, char const* usagestr, bool critical)
        {
            auto ext = x509_extension::make_key_usage(usagestr, critical);
            add_extension(ctx, std::move(ext));
        }

        void set_ext_key_usage(context& ctx, char const* usagestr, bool critical)
        {
            auto ext = x509_extension::make_ext_key_usage(usagestr, critical);
            add_extension(ctx, std::move(ext));
        }

        void set_subject_alt_names(context& ctx, owned<STACK_OF(GENERAL_NAME)> const& altnames)
        {
            auto ext = x509_extension::make_subject_alt_names(altnames);
            add_extension(ctx, std::move(ext));
        }

        void set_subject_alt_names(context& ctx, std::initializer_list<x509::saltname> const& altnames)
        {
            auto gnames = sk::make<GENERAL_NAME>();
            for (auto const& name : altnames)
                gnames.push(general_name::copy(name));

            return set_subject_alt_names(ctx, gnames.mine());
        }

        void set_subject_alt_names(context& ctx, std::vector<x509::saltname> const& altnames)
        {
            auto gnames = sk::make<GENERAL_NAME>();
            for (auto const& name : altnames)
                gnames.push(general_name::copy(name));

            return set_subject_alt_names(ctx, gnames.mine());
        }

    } // namespace builder
} // namespace x509_req
} // namespace ossl
