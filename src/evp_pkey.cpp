//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <tuple>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "cppossl/bio.hpp"
#include "cppossl/error.hpp"
#include "cppossl/evp_pkey.hpp"

namespace ossl {
namespace evp_pkey {

    owned<::EVP_PKEY> retain(roref key)
    {
        EVP_PKEY_up_ref(const_cast<::EVP_PKEY*>(key.get()));
        return owned<::EVP_PKEY> { const_cast<::EVP_PKEY*>(key.get()) };
    }

    bool equal(roref lhs, roref rhs)
    {
        return EVP_PKEY_eq(lhs.get(), rhs.get()) == 1;
    }

} // namespace evp_pkey
} // namespace ossl
