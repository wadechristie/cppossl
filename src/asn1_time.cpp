//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/asn1_time.hpp"
#include "cppossl/error.hpp"

namespace ossl {

asn1_time_t make_asn1_time_now()
{
    return make_asn1_time(std::chrono::seconds::zero());
}

asn1_time_t make_asn1_time(std::chrono::seconds const& from_now)
{
    asn1_time_t obj { ASN1_TIME_new() };
    if (obj == nullptr)
        CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to allocate new OpenSSL ASN1_TIME object."); // LCOV_EXCL_LINE

    if (X509_time_adj_ex(obj.get(), 0, from_now.count(), nullptr) == 0)
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to build X509_REVOKED revocation date."); // LCOV_EXCL_LINE

    return obj;
} // LCOV_EXCL_LINE

asn1_time_t make_asn1_time(time_t const& unixts)
{
    time_t const now = time(nullptr);
    return make_asn1_time(std::chrono::seconds(now - unixts));
}

} // namespace ossl
