//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <tuple>

#include <cppossl/asn1_string.hpp>
#include <cppossl/error.hpp>
#include <cppossl/raii.hpp>

namespace ossl {
namespace der {

    template <typename T>
    struct traits
    {
        static_assert(sizeof(T) != sizeof(T), "Missing CPPOSSL DER traits specialization.");
    };

    class encoded_value
    {
    public:
        inline encoded_value(uint8_t* data, int size)
            : _data(data)
            , _size(size)
        {
        }

        ~encoded_value() = default;

        inline bool has_data() const
        {
            return _data != nullptr;
        }

        inline uint8_t const* data() const
        {
            return _data.get();
        }

        inline int size() const
        {
            return _size;
        }

        inline std::tuple<uint8_t*, int> release()
        {
            auto ret = std::make_tuple(_data.release(), _size);
            _size = 0;
            return ret;
        }

        inline owned<::ASN1_OCTET_STRING> to_octet_string()
        {
            auto str = make<asn1::OCTET_STRING>();
            std::tie(str->data, str->length) = release();
            return str;
        }

    private:
        raii::owned<uint8_t> _data;
        int _size;
    };

    template <typename T>
    encoded_value encode(raii::roref<T> object)
    {
        static_assert(!std::is_same<T, ::asn1_string_st>::value);
        uint8_t* data = nullptr;
        int const size = der::traits<T>::encode(object.get(), &data);
        if (size < 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to encode object to DER.");
        return encoded_value(data, size);
    }

    template <typename T>
    encoded_value encode(raii::owned<T> const& object)
    {
        return encode(raii::roref<T>(object));
    }

#define DEFINE_OSSL_DER_OBJECT_TRAITS(T, V, EncodeFn) \
    template <>                                       \
    struct traits<T, V>                               \
    {                                                 \
        static auto constexpr encode = EncodeFn;      \
    }

#define DEFINE_OSSL_DER_TRAITS_AUTO(TypeT) DEFINE_OSSL_DER_OBJECT_TRAITS(TypeT, -1, i2d_##TypeT)

#define OSSL_DER_STRING_TYPE_MAP(X_) \
    X_(ASN1_INTEGER)                 \
    X_(ASN1_BIT_STRING)              \
    X_(ASN1_OCTET_STRING)            \
    X_(ASN1_ENUMERATED)              \
    X_(ASN1_UTF8STRING)              \
    X_(ASN1_IA5STRING)

    template <>
    inline encoded_value encode<::asn1_string_st>(raii::roref<::asn1_string_st> object)
    {
        uint8_t* data = nullptr;
        int size = -1;

#define _CASE(T)                             \
    case V_##T:                              \
        size = i2d_##T(object.get(), &data); \
        break;

        switch (object.get()->type)
        {
            OSSL_DER_STRING_TYPE_MAP(_CASE)

        default:
            std::runtime_error("Failed to encoded ASN.1 string, unhandled type.");
        }

#undef _CASE

        if (size < 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to encode object to DER.");

        return encoded_value(data, size);
    }

} // namespace der
} // namespace ossl
