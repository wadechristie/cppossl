//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/asn1_bit_string.hpp"
#include "cppossl/error.hpp"

namespace ossl {
namespace asn1 {
    namespace bit_string {

        void set_bit(rwref bitstr, uint8_t index, bool value)
        {
            if (ASN1_BIT_STRING_set_bit(bitstr.get(), static_cast<int>(index), value ? 1 : 0) != 1)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                    "Failed to set bit in ASN1_BIT_STRING.");
        }

        bool is_set(roref bitstr, uint8_t index)
        {
            return ASN1_BIT_STRING_get_bit(bitstr.get(), static_cast<int>(index));
        }

    } // namespace bit_string
} // namespace asn1
} // namespace ossl
