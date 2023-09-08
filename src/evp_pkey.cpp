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

evp_pkey_t new_ref(evp_pkey_t const& key)
{
    EVP_PKEY_up_ref(key.get());
    return evp_pkey_t { key.get() };
}

bool equal(evp_pkey_t const& lhs, evp_pkey_t const& rhs)
{
    return EVP_PKEY_eq(lhs.get(), rhs.get()) == 1;
}

} // namespace ossl
