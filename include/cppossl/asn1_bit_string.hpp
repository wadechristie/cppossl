//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cppossl/raii.hpp>

namespace ossl {
namespace asn1 {
    namespace bit_string {

        /**
         * \defgroup asn1_bit_string OpenSSL ASN1_BIT_STRING
         */
        /**@{*/

        /** @brief ASN1_BIT_STRING readonly reference.*/
        using roref = raii::roref<::ASN1_BIT_STRING>;

        /** @brief ASN1_BIT_STRING readwrite reference.*/
        using rwref = raii::rwref<::ASN1_BIT_STRING>;

        void set_bit(rwref bitstr, uint8_t index, bool value);

        inline void set(rwref bitstr, uint8_t index)
        {
            set_bit(bitstr, index, true);
        }

        inline void clear(rwref bitstr, uint8_t index)
        {
            set_bit(bitstr, index, false);
        }

        bool is_set(roref bitstr, uint8_t index);

        /**@}*/

    } // namespace bit_string
} // namespace asn1
} // namespace ossl
