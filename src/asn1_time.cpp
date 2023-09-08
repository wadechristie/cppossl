//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/asn1_time.hpp"
#include "cppossl/error.hpp"

namespace ossl {
namespace asn1_time {

    asn1_time_t now()
    {
        return offset(std::chrono::seconds::zero());
    }

    asn1_time_t offset(std::chrono::seconds const& from_now)
    {
        auto t = asn1_time_t::make();
        set_offset(t.get(), from_now);
        return t;
    } // LCOV_EXCL_LINE

    asn1_time_t from_unix(time_t const& unixts)
    {
        time_t const now = time(nullptr);
        return offset(std::chrono::seconds(now - unixts));
    }

    void set_offset(::ASN1_TIME* t, std::chrono::seconds const& from_now)
    {
        if (X509_time_adj_ex(t, 0, from_now.count(), nullptr) == 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to update ASN1_TIME."); // LCOV_EXCL_LINE
    } // LCOV_EXCL_LINE

    void set_unix(::ASN1_TIME* t, time_t const& unixts)
    {
        time_t const now = time(nullptr);
        set_offset(t, std::chrono::seconds(now - unixts));
    }

} // namespace asn1_time
} // namespace ossl
