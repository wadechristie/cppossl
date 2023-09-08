//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <utility>

#include <openssl/types.h>
#include <openssl/x509v3.h>

#include <cppossl/error.hpp>

namespace ossl {

/**
 * \defgroup raii OpenSSL RAII Containers
 */
/**@{*/

namespace raii {

    template <typename T>
    struct traits {
        static_assert(sizeof(T) != sizeof(T), "Missing OpenSSL C++ RIAA traits specialization.");
    };

    template <typename T>
    class ossl_raii_ptr {
    public:
        template <typename... ArgsT>
        static ossl_raii_ptr<T> make(ArgsT&&... args)
        {
            return ossl_raii_ptr<T> { traits<T>::newfn(std::forward<ArgsT>(args)...) };
        }

        ossl_raii_ptr() noexcept = default;

        explicit ossl_raii_ptr(T* ptr) noexcept
            : _ptr(ptr)
        {
        }

        ossl_raii_ptr(ossl_raii_ptr&& move) noexcept
        {
            std::swap(_ptr, move._ptr);
        }

        ossl_raii_ptr& operator=(ossl_raii_ptr&& move) noexcept
        {
            std::swap(_ptr, move._ptr);
            return *this;
        }

        ossl_raii_ptr(ossl_raii_ptr const&) = delete;
        ossl_raii_ptr& operator=(ossl_raii_ptr const&) = delete;

        ~ossl_raii_ptr() noexcept
        {
            if (_ptr != nullptr)
                traits<T>::freefn(_ptr);
        }

        bool operator==(std::nullptr_t const&) const
        {
            return _ptr == nullptr;
        }

        bool operator!=(std::nullptr_t const&) const
        {
            return _ptr != nullptr;
        }

        operator bool() const
        {
            return _ptr != nullptr;
        }

        T* operator->() const
        {
            return _ptr;
        }

        T* get() noexcept
        {
            return _ptr;
        }

        T* get() const noexcept
        {
            return _ptr;
        }

        T* release() noexcept
        {
            T* ret = nullptr;
            std::swap(_ptr, ret);
            return ret;
        }

    private:
        T* _ptr { nullptr };
    };

} // namespace _

#define DEFINE_OSSL_RAII_TRAITS(TypeT, NewFn, FreeFN) \
    template <>                                       \
    struct raii::traits<TypeT> {                      \
        static auto constexpr newfn = NewFn;          \
        static auto constexpr freefn = FreeFN;        \
    }

#define DEFINE_OSSL_RAII_TRAITS_AUTO(TypeT) DEFINE_OSSL_RAII_TRAITS(TypeT, TypeT##_new, TypeT##_free)
#define DEFINE_OSSL_RAII_TRAITS_AUTO_STACK(TypeT)                                                       \
    DEFINE_OSSL_RAII_TRAITS(                                                                            \
        STACK_OF(TypeT),                                                                                \
        []() {                                                                                          \
            auto sk = sk_##TypeT##_new_null();                                                          \
            if (sk == nullptr)                                                                          \
                CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to allocate new OpenSSL " #TypeT " stack object."); \
            return sk;                                                                                  \
        },                                                                                              \
        [](STACK_OF(TypeT) * p) { sk_##TypeT##_pop_free(p, TypeT##_free); };)

DEFINE_OSSL_RAII_TRAITS_AUTO(::ASN1_STRING);
DEFINE_OSSL_RAII_TRAITS(::BIGNUM, ::BN_new, ::BN_free);
DEFINE_OSSL_RAII_TRAITS_AUTO(::BIO);
DEFINE_OSSL_RAII_TRAITS(char, nullptr, [](char* p) { OPENSSL_free(p); });
DEFINE_OSSL_RAII_TRAITS_AUTO(::DIST_POINT);
DEFINE_OSSL_RAII_TRAITS_AUTO_STACK(DIST_POINT);
DEFINE_OSSL_RAII_TRAITS_AUTO(::DIST_POINT_NAME);
DEFINE_OSSL_RAII_TRAITS_AUTO(::EVP_PKEY);
DEFINE_OSSL_RAII_TRAITS_AUTO(::GENERAL_NAME);
DEFINE_OSSL_RAII_TRAITS_AUTO_STACK(GENERAL_NAME);
DEFINE_OSSL_RAII_TRAITS_AUTO(::X509);
DEFINE_OSSL_RAII_TRAITS_AUTO(::X509_CRL);
DEFINE_OSSL_RAII_TRAITS_AUTO_STACK(X509_CRL);
DEFINE_OSSL_RAII_TRAITS_AUTO(::X509_EXTENSION);
DEFINE_OSSL_RAII_TRAITS_AUTO_STACK(X509_EXTENSION);
DEFINE_OSSL_RAII_TRAITS_AUTO(::X509_NAME);
DEFINE_OSSL_RAII_TRAITS_AUTO(::X509_REQ);
DEFINE_OSSL_RAII_TRAITS_AUTO(::X509_REVOKED);
DEFINE_OSSL_RAII_TRAITS_AUTO(::X509_STORE);
DEFINE_OSSL_RAII_TRAITS_AUTO(::X509_STORE_CTX);
DEFINE_OSSL_RAII_TRAITS_AUTO(::X509_VERIFY_PARAM);

using asn1_bit_string_t = raii::ossl_raii_ptr<::ASN1_STRING>;
using asn1_ia5string_t = raii::ossl_raii_ptr<::ASN1_STRING>;
using asn1_enumerated_t = raii::ossl_raii_ptr<::ASN1_STRING>;
using asn1_octect_string_t = raii::ossl_raii_ptr<::ASN1_STRING>;
using asn1_time_t = raii::ossl_raii_ptr<::ASN1_TIME>;
using bignum_t = raii::ossl_raii_ptr<::BIGNUM>;
using bio_t = raii::ossl_raii_ptr<::BIO>;
using ossl_cstring_t = raii::ossl_raii_ptr<char>;
using dist_point_t = raii::ossl_raii_ptr<::DIST_POINT>;
using dist_point_sk_t = raii::ossl_raii_ptr<STACK_OF(DIST_POINT)>;
using dist_point_name_t = raii::ossl_raii_ptr<::DIST_POINT_NAME>;
using evp_pkey_t = raii::ossl_raii_ptr<::EVP_PKEY>;
using general_name_t = raii::ossl_raii_ptr<::GENERAL_NAME>;
using general_name_sk_t = raii::ossl_raii_ptr<STACK_OF(GENERAL_NAME)>;
using x509_t = raii::ossl_raii_ptr<::X509>;
using x509_crl_t = raii::ossl_raii_ptr<::X509_CRL>;
using x509_crl_sk_t = raii::ossl_raii_ptr<STACK_OF(X509_CRL)>;
using x509_extension_t = raii::ossl_raii_ptr<::X509_EXTENSION>;
using x509_extension_sk_t = raii::ossl_raii_ptr<STACK_OF(X509_EXTENSION)>;
using x509_name_t = raii::ossl_raii_ptr<::X509_NAME>;
using x509_req_t = raii::ossl_raii_ptr<::X509_REQ>;
using x509_revoked_t = raii::ossl_raii_ptr<::X509_REVOKED>;
using x509_store_t = raii::ossl_raii_ptr<::X509_STORE>;
using x509_store_ctx_t = raii::ossl_raii_ptr<::X509_STORE_CTX>;
using x509_verify_param_t = raii::ossl_raii_ptr<::X509_VERIFY_PARAM>;

/**@}*/

} // namespace ossl
