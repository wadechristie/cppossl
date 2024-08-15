//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <limits>
#include <string_view>

#include <cppossl/raii.hpp>

namespace ossl {
namespace asn1 {

    enum string_type : int
    {
        INTEGER = V_ASN1_INTEGER,
        BIT_STRING = V_ASN1_BIT_STRING,
        OCTET_STRING = V_ASN1_OCTET_STRING,
        ENUMERATED = V_ASN1_ENUMERATED,
        UTF8STRING = V_ASN1_UTF8STRING,
        IA5STRING = V_ASN1_IA5STRING,
    };

} // namespace asn1

/**
 * @brief Special version of `ossl::make()` for `ANS1_STRING` types.
 */
template <asn1::string_type T>
raii::owned<::asn1_string_st> make()
{
    return ossl::make<::asn1_string_st>(static_cast<std::underlying_type<asn1::string_type>::type>(T));
}

inline void set(raii::rwref<::ASN1_STRING> str, std::string_view value)
{
    if (ASN1_STRING_type(str.get()) != asn1::IA5STRING && ASN1_STRING_type(str.get()) != asn1::UTF8STRING)
        throw std::runtime_error("Operation not supported on ASN1_STRING type.");

    if (value.size() > std::numeric_limits<int>::max())
        throw std::runtime_error( // LCOV_EXCL_LINE
            "Input string too large for ASN1_STRING construction.");

    if (!ASN1_STRING_set(str.get(), value.data(), static_cast<int>(value.size())))
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set ASN1_STRING value."); // LCOV_EXCL_LINE
}

template <asn1::string_type T>
raii::owned<::asn1_string_st> make(std::string_view value)
{
    static_assert(T == asn1::IA5STRING || T == asn1::UTF8STRING);
    raii::owned<::asn1_string_st> str = make<T>();
    set(str, value);
    return str;
}

} // namespace ossl
