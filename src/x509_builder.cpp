//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <sstream>

#include "cppossl/error.hpp"
#include "cppossl/stack.hpp"
#include "cppossl/x509_builder.hpp"
#include "cppossl/x509_extension.hpp"

namespace ossl {
namespace x509 {

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
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to add new extension to X.509 object."); // LCOV_EXCL_LINE
        }

        void copy_extensions(x509::rwref x509, x509_req::roref req, bool overwrite)
        {
            ossl::owned<STACK_OF(X509_EXTENSION)> req_exts { X509_REQ_get_extensions(
                const_cast<::X509_REQ*>(req.get())) };
            if (req_exts == nullptr)
                return;

            for (int i = 0; i < sk_X509_EXTENSION_num(req_exts.get()); ++i)
            {
                X509_EXTENSION* ext = sk_X509_EXTENSION_value(req_exts.get(), i);
                ASN1_OBJECT const* obj = X509_EXTENSION_get_object(ext);
                int const nid = OBJ_obj2nid(obj);

                int const idx = X509_get_ext_by_NID(x509.get(), nid, -1);
                if (idx >= 0)
                {
                    if (!overwrite)
                        continue;

                    remove_ext_by_nid(x509, nid);
                }

                add_extension(x509, ext);
            }
        }

    } // namespace _

    builder::builder(x509_req::roref req, bool copy_exts)
        : builder()
    {
        // copy subject
        set_subject(X509_REQ_get_subject_name(req.get()));

        // copy public key
        ossl::owned<EVP_PKEY> pubkey(X509_REQ_get_pubkey(const_cast<::X509_REQ*>(req.get())));
        if (pubkey == nullptr)
            CPPOSSL_THROW_ERRNO(EINVAL, "Certificate request is missing a public key."); // LCOV_EXCL_LINE
        set_public_key(pubkey);

        if (copy_exts)
            _::copy_extensions(_x509, req, /*overwrite=*/false);
    }

    owned<::X509> builder::reset()
    {
        // stash the prev object for return
        auto prev = std::move(_x509);

        // start with a fresh X.509 object
        _x509 = make<::X509>();

        if (X509_set_version(_x509.get(), X509_VERSION_3) == 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 version."); // LCOV_EXCL_LINE

        // default to a random serial number
        set_random_serialno();

        // default notBefore & notAfter to now
        auto const now = asn1::time::now();
        set_not_before(now);
        set_not_after(now);

        return prev;
    }

    builder& builder::set_serialno(ossl::raii::roref<::BIGNUM> serial)
    {
        if (BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(_x509.get())) == 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to convert BIGNUM serial number to OpenSSL ASN1_INTEGER."); // LCOV_EXCL_LINE

        return *this;
    }

    builder& builder::set_random_serialno()
    {
        auto randomserial = ossl::make<BIGNUM>();
        if (BN_rand(randomserial.get(), 64, 0, 0) == 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to generate a random serial number."); // LCOV_EXCL_LINE

        return set_serialno(randomserial);
    }

    builder& builder::set_public_key(ossl::evp_pkey::roref pubkey)
    {
        if (!X509_set_pubkey(_x509.get(), const_cast<::EVP_PKEY*>(pubkey.get())))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate public key."); // LCOV_EXCL_LINE
        return *this;
    }

    builder& builder::set_subject(x509_name::roref name)
    {
        if (!X509_set_subject_name(_x509.get(), name.get()))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate subject."); // LCOV_EXCL_LINE
        return *this;
    }

    builder& builder::set_issuer(x509_name::roref name)
    {
        if (!X509_set_issuer_name(_x509.get(), name.get()))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate issuer."); // LCOV_EXCL_LINE
        return *this;
    }

    builder& builder::set_not_before(asn1::time::roref not_before)
    {
        if (!X509_set1_notBefore(_x509.get(), not_before.get()))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate notBefore."); // LCOV_EXCL_LINE
        return *this;
    }

    builder& builder::set_not_after(asn1::time::roref not_after)
    {
        if (!X509_set1_notAfter(_x509.get(), not_after.get()))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set X.509 certificate notAfter."); // LCOV_EXCL_LINE
        return *this;
    }

    builder& builder::set_basic_constraints_ext(bool ca, int pathlen)
    {
        auto const ext = x509_extension::make_basic_constraints(ca, pathlen);
        _::add_extension(_x509, ext);
        return *this;
    }

    builder& builder::set_key_usage_ext(std::string_view const& usagestr, bool critical)
    {
        auto const ext = x509_extension::make_key_usage(usagestr, critical);
        _::add_extension(_x509, ext);
        return *this;
    }

    builder& builder::set_key_usage_ext(raii::roref<::ASN1_BIT_STRING> usage, bool critical)
    {
        auto const ext = x509_extension::make_key_usage(usage, critical);
        _::add_extension(_x509, ext);
        return *this;
    }

    builder& builder::set_ext_key_usage_ext(std::string_view const& usagestr, bool critical)
    {
        auto const ext = x509_extension::make_ext_key_usage(usagestr, critical);
        _::add_extension(_x509, ext);
        return *this;
    }

    builder& builder::set_subject_alt_names_ext(owned<STACK_OF(GENERAL_NAME)> const& altnames)
    {
        owned<::X509_EXTENSION> ext { X509V3_EXT_i2d(NID_subject_alt_name, /*crit=*/0, altnames.get()) };
        if (ext == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to create OpenSSL subject alt name X.509 extension object.");

        _::add_extension(_x509, ext);
        return *this;
    }

    builder& builder::set_subject_alt_names_ext(std::initializer_list<owned<::GENERAL_NAME>> const& altnames)
    {
        auto gnames = make<STACK_OF(GENERAL_NAME)>();
        for (auto const& name : altnames)
            stack::push(gnames, general_name::copy(name));

        return set_subject_alt_names_ext(gnames);
    }

    builder& builder::set_subject_key_id_ext()
    {
        owned<::EVP_PKEY> const pubkey { X509_get_pubkey(_x509.get()) };
        if (pubkey == nullptr)
            CPPOSSL_THROW_ERRNO(EINVAL, "Cannot set subject key identifier extension prior to setting the public key");

        X509V3_CTX ctx {};
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, nullptr, _x509.get(), nullptr, nullptr, 0);

        char const* value = "hash";
        ossl::owned<::X509_EXTENSION> ext { X509V3_EXT_conf_nid(
            nullptr, &ctx, NID_subject_key_identifier, const_cast<char*>(value)) };
        if (ext == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to create X.509 subjectKeyIdentifier extension object."); // LCOV_EXCL_LINE

        _::add_extension(_x509, ext);

        return *this;
    }

    builder& builder::set_authority_key_id_ext(x509::roref cacert)
    {
        auto const ext = x509_extension::make_authority_key_id(cacert);
        _::add_extension(_x509, ext);
        return *this;
    }

    builder& builder::set_crl_distribution_point_ext(raii::roref<STACK_OF(DIST_POINT)> crldists)
    {
        auto const ext = x509_extension::make_crl_distribution_point(crldists);
        _::add_extension(_x509, ext);
        return *this;
    }

    builder& builder::set_authority_access_info_ext(std::string_view const& accessinfo)
    {
        auto const ext = x509_extension::make_authority_access_info(accessinfo);
        _::add_extension(_x509, ext);
        return *this;
    }

    ossl::owned<::X509> builder::sign(
        ossl::x509::roref issuer_cert, ossl::evp_pkey::roref issuer_key, EVP_MD const* digest)
    {
        CPPOSSL_ASSERT(digest != nullptr);

        owned<::EVP_PKEY> const pubkey { X509_get_pubkey(_x509.get()) };
        if (pubkey == nullptr)
            CPPOSSL_THROW_ERRNO(EINVAL, "X.509 public key was not set");

        set_issuer(X509_get_subject_name(issuer_cert.get()));

        if (X509_sign(_x509.get(), const_cast<::EVP_PKEY*>(issuer_key.get()), digest) <= 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to sign X.509 certificate."); // LCOV_EXCL_LINE

        return reset();
    }

    ossl::owned<::X509> builder::selfsign(ossl::evp_pkey::roref key, EVP_MD const* digest)
    {
        CPPOSSL_ASSERT(digest != nullptr);

        owned<::EVP_PKEY> const pubkey { X509_get_pubkey(_x509.get()) };
        if (pubkey == nullptr)
        {
            set_public_key(key);
        }
        else
        {
            if (!evp_pkey::equal(pubkey, key))
                CPPOSSL_THROW_ERRNO(EINVAL, "X.509 public key does not match self-signing key");
        }

        set_issuer(X509_get_subject_name(_x509.get()));

        if (X509_sign(_x509.get(), const_cast<::EVP_PKEY*>(key.get()), digest) <= 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to sign X.509 certificate."); // LCOV_EXCL_LINE

        if (!ossl::x509::check_key(_x509, key))
            throw std::runtime_error("Failed to verify X.509 the self-signed certificate."); // LCOV_EXCL_LINE

        return reset();
    }

} // namespace x509
} // namespace ossl
