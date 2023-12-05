//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <cppossl/raii.hpp>

namespace ossl {
namespace unittest {

    inline ::EVP_MD const* default_digest()
    {
        return ::EVP_sha256();
    }

    class test_pkey
    {
        size_t const index { 0 };

        test_pkey() = delete;

    public:
        inline explicit test_pkey(size_t index)
            : index(index)
        {
        }

        std::string pem() const;
        owned<::EVP_PKEY> load() const;
    };

    static test_pkey rsa_key_one(0);
    static test_pkey rsa_key_two(1);
    static test_pkey rsa_key_three(2);
} // namespace  unittest
} // namespace ossl
