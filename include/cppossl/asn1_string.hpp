//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cppossl/raii.hpp>

namespace ossl {
namespace asn1 {

    enum string_type
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
    return raii::owned<::asn1_string_st> { ASN1_STRING_type_new(
        static_cast<std::underlying_type<asn1::string_type>::type>(T)) };
}

} // namespace ossl
