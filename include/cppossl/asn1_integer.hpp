//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cppossl/asn1_string.hpp>
#include <cppossl/raii.hpp>

namespace ossl {
namespace asn1 {
    namespace integer {

        /**
         * \defgroup OpenSSL ASN1_INTEGER
         */
        /**@{*/

        /** @brief ASN1_INTEGER readonly reference.*/
        using roref = raii::roref<::ASN1_INTEGER>;

        /** @brief ASN1_INTEGER readwrite reference.*/
        using rwref = raii::rwref<::ASN1_INTEGER>;

        owned<::ASN1_INTEGER> make(uint64_t value);
        owned<::ASN1_INTEGER> make(ossl::raii::roref<::BIGNUM> value);

        int cmp(roref left, roref right);

        inline bool equal(roref left, roref right)
        {
            return cmp(left, right) == 0;
        }

        /**@}*/

    } // namespace integer
} // namespace asn1
} // namespace ossl
