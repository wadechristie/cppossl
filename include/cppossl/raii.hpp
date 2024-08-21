//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <utility>

#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cppossl/error.hpp>

namespace ossl {

/**
 * \defgroup raii OpenSSL RAII Containers
 */
/**@{*/

namespace raii {

    template <typename T>
    struct traits
    {
        static_assert(sizeof(T) != sizeof(T), "Missing CPPOSSL RIAA traits specialization.");
    };

    template <typename T>
    class owned
    {
    public:
        typedef T type;

        template <typename... ArgsT>
        static owned<T> make(ArgsT&&... args)
        {
            return owned<T> { traits<T>::newfn(std::forward<ArgsT>(args)...) };
        }

        owned() noexcept = default;

        explicit owned(T* ptr) noexcept
            : _ptr(ptr)
        {
        }

        owned(owned&& move) noexcept
        {
            std::swap(_ptr, move._ptr);
        }

        owned& operator=(owned&& move) noexcept
        {
            std::swap(_ptr, move._ptr);
            return *this;
        }

        owned(owned const&) = delete;
        owned& operator=(owned const&) = delete;

        ~owned() noexcept
        {
            destroy();
        }

        operator bool() const noexcept
        {
            return _ptr != nullptr;
        }

        bool operator==(std::nullptr_t const&) const noexcept
        {
            return _ptr == nullptr;
        }

        bool operator!=(std::nullptr_t const&) const noexcept
        {
            return _ptr != nullptr;
        }

        T* operator->() const noexcept
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

        T** capture() noexcept
        {
            destroy();
            return &_ptr;
        }

    private:
        void destroy()
        {
            if (_ptr != nullptr)
            {
                traits<T>::freefn(_ptr);
                _ptr = nullptr;
            }
        }
        T* _ptr { nullptr };
    };

    template <typename T>
    class rwref
    {
    public:
        typedef T type;

        rwref(T* ptr) noexcept
            : _ptr(ptr)
        {
        }

        rwref(owned<T> const& owned) noexcept
            : _ptr(owned.get())
        {
        }

        rwref(rwref&&) = delete;
        rwref& operator=(rwref&&) = delete;

        rwref(rwref const&) = default;
        rwref& operator=(rwref const&) = delete;

        ~rwref() noexcept
        {
        }

        operator bool() const noexcept
        {
            return _ptr != nullptr;
        }

        bool operator==(std::nullptr_t const&) const noexcept
        {
            return _ptr == nullptr;
        }

        bool operator!=(std::nullptr_t const&) const noexcept
        {
            return _ptr != nullptr;
        }

        T* get() noexcept
        {
            return _ptr;
        }

        T* get() const noexcept
        {
            return _ptr;
        }

    private:
        T* _ptr { nullptr };
    };

    template <typename T>
    class roref
    {
    public:
        typedef T type;

        roref(T const* ptr) noexcept
            : _ptr(ptr)
        {
        }

        roref(rwref<T> const& ref) noexcept
            : _ptr(ref)
        {
        }

        roref(owned<T> const& owned) noexcept
            : _ptr(owned.get())
        {
        }

        roref(roref&&) = delete;
        roref& operator=(roref&&) = delete;

        roref(roref const&) = default;
        roref& operator=(roref const&) = delete;

        ~roref() noexcept
        {
        }

        operator bool() const noexcept
        {
            return _ptr != nullptr;
        }

        bool operator==(std::nullptr_t const&) const noexcept
        {
            return _ptr == nullptr;
        }

        bool operator!=(std::nullptr_t const&) const noexcept
        {
            return _ptr != nullptr;
        }

        T const* get() noexcept
        {
            return _ptr;
        }

    private:
        T const* _ptr { nullptr };
    };

} // namespace raii

#define DEFINE_OSSL_RAII_OBJECT_TRAITS(TypeT, NewFn, FreeFN) \
    template <>                                              \
    struct raii::traits<TypeT>                               \
    {                                                        \
        using stack_type = STACK_OF(TypeT);                  \
        static auto constexpr name = #TypeT;                 \
        static auto constexpr newfn = NewFn;                 \
        static auto constexpr freefn = FreeFN;               \
    }

#define DEFINE_OSSL_RAII_STACK_TRAITS(TypeT, ElemT, NewFn, FreeFN) \
    template <>                                                    \
    struct raii::traits<TypeT>                                     \
    {                                                              \
        using elem_type = ElemT;                                   \
        static bool constexpr is_stack = true;                     \
        static auto constexpr name = #TypeT;                       \
        static auto constexpr newfn = NewFn;                       \
        static auto constexpr freefn = FreeFN;                     \
    }

#define DEFINE_OSSL_RAII_TRAITS_AUTO(TypeT) DEFINE_OSSL_RAII_OBJECT_TRAITS(TypeT, TypeT##_new, TypeT##_free)
#define DEFINE_OSSL_RAII_TRAITS_AUTO_STACK(TypeT)                                                       \
    DEFINE_OSSL_RAII_STACK_TRAITS(                                                                      \
        STACK_OF(TypeT),                                                                                \
        TypeT,                                                                                          \
        []() {                                                                                          \
            auto sk = sk_##TypeT##_new_null();                                                          \
            if (sk == nullptr)                                                                          \
                CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to allocate new OpenSSL " #TypeT " stack object."); \
            return sk;                                                                                  \
        },                                                                                              \
        [](STACK_OF(TypeT) * sk) { sk_##TypeT##_pop_free(sk, TypeT##_free); })

DEFINE_OSSL_RAII_TRAITS_AUTO(ASN1_TYPE);
DEFINE_OSSL_RAII_TRAITS_AUTO(DIST_POINT);
DEFINE_OSSL_RAII_TRAITS_AUTO(DIST_POINT_NAME);
DEFINE_OSSL_RAII_TRAITS_AUTO(EVP_PKEY);
DEFINE_OSSL_RAII_TRAITS_AUTO(GENERAL_NAME);
DEFINE_OSSL_RAII_TRAITS_AUTO(X509);
DEFINE_OSSL_RAII_TRAITS_AUTO(X509_CRL);
DEFINE_OSSL_RAII_TRAITS_AUTO(X509_EXTENSION);
DEFINE_OSSL_RAII_TRAITS_AUTO(X509_INFO);
DEFINE_OSSL_RAII_TRAITS_AUTO(X509_NAME);
DEFINE_OSSL_RAII_TRAITS_AUTO(X509_NAME_ENTRY);
DEFINE_OSSL_RAII_TRAITS_AUTO(X509_REQ);
DEFINE_OSSL_RAII_TRAITS_AUTO(X509_REVOKED);
DEFINE_OSSL_RAII_TRAITS_AUTO(X509_STORE);
DEFINE_OSSL_RAII_TRAITS_AUTO(X509_STORE_CTX);
DEFINE_OSSL_RAII_TRAITS_AUTO(X509_VERIFY_PARAM);

DEFINE_OSSL_RAII_OBJECT_TRAITS(ASN1_STRING, ASN1_STRING_type_new, ASN1_STRING_free);
DEFINE_OSSL_RAII_OBJECT_TRAITS(BIGNUM, BN_new, BN_free);
DEFINE_OSSL_RAII_OBJECT_TRAITS(BIO, BIO_new, BIO_free_all);
DEFINE_OSSL_RAII_OBJECT_TRAITS(char, nullptr, [](char* p) { OPENSSL_free(p); });
DEFINE_OSSL_RAII_OBJECT_TRAITS(uint8_t, nullptr, [](uint8_t* p) { OPENSSL_free(p); });

DEFINE_OSSL_RAII_TRAITS_AUTO_STACK(DIST_POINT);
DEFINE_OSSL_RAII_TRAITS_AUTO_STACK(GENERAL_NAME);
DEFINE_OSSL_RAII_TRAITS_AUTO_STACK(X509);
DEFINE_OSSL_RAII_TRAITS_AUTO_STACK(X509_CRL);
DEFINE_OSSL_RAII_TRAITS_AUTO_STACK(X509_EXTENSION);
DEFINE_OSSL_RAII_TRAITS_AUTO_STACK(X509_INFO);

template <typename T>
using owned = raii::owned<T>;

template <typename T, typename... ArgsT>
raii::owned<T> make(ArgsT&&... args)
{
    return raii::owned<T> { raii::traits<T>::newfn(std::forward<ArgsT>(args)...) };
}

/**@}*/

} // namespace ossl
