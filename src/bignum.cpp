//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/bignum.hpp"
#include "cppossl/error.hpp"

namespace ossl {
namespace bignum {

    owned<::BIGNUM> make(uint64_t value)
    {
        static_assert(sizeof(uint64_t) == sizeof(BN_ULONG));
        owned<::BIGNUM> bn = ossl::make<::BIGNUM>();
        if (BN_set_word(bn.get(), value) == 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to create BIGNUM object from integer value."); // LCOV_EXCL_LINE
        return bn;
    } // LCOV_EXCL_LINE

    owned<::BIGNUM> make(asn1::integer::roref value)
    {
        if (ASN1_STRING_type(value.get()) != asn1::INTEGER)
            throw std::runtime_error("Invalid ASN1_STRING object type, expected V_ASN1_INTEGER.");

        owned<::BIGNUM> bn = ossl::make<::BIGNUM>();
        if (ASN1_INTEGER_to_BN(value.get(), bn.get()) == 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to convert ASN1_INTEGER object to BIGNUM object."); // LCOV_EXCL_LINE
        return bn;
    } // LCOV_EXCL_LINE

    owned<::BIGNUM> random()
    {
        auto bn = ossl::make<BIGNUM>();
        if (BN_rand(bn.get(), 64, 0, 0) == 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to generate a random BIGNUM object."); // LCOV_EXCL_LINE
        return bn;
    } // LCOV_EXCL_LINE

    std::string to_dec_string(roref bn)
    {
        auto const s = raii::own<char>(BN_bn2dec(bn.get()));
        if (!s)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to convert BIGNUM to decimal string."); // LCOV_EXCL_LINE
        return std::string(s.get());
    }

    std::string to_hex_string(roref bn)
    {
        auto const s = raii::own<char>(BN_bn2hex(bn.get()));
        if (!s)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to convert BIGNUM to hex string."); // LCOV_EXCL_LINE
        return std::string(s.get());
    }

} // namespace bignum
} // namespace ossl
