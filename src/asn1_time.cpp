//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/asn1_time.hpp"
#include "cppossl/error.hpp"

namespace ossl {
namespace asn1_time {

    int cmp(roref left, roref right)
    {
        auto const result = ASN1_TIME_compare(left.get(), right.get());
        if (result == -2)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Encountered an error while attempting to compare two OpenSSL ASN1_TIME objects.");
        return result;
    }

    owned<::ASN1_TIME> now()
    {
        return offset(std::chrono::seconds::zero());
    }

    owned<::ASN1_TIME> offset(std::chrono::seconds const& from_now)
    {
        owned<::ASN1_TIME> t { X509_time_adj_ex(nullptr, 0, from_now.count(), nullptr) };
        if (t == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to create ASN1_TIME from offset."); // LCOV_EXCL_LINE
        return t;
    } // LCOV_EXCL_LINE

    owned<::ASN1_TIME> from_unix(time_t const& unixts)
    {
        time_t tmp = unixts;
        owned<::ASN1_TIME> t { X509_time_adj_ex(nullptr, 0, 0, &tmp) };
        if (t == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to update ASN1_TIME from unix timestamp."); // LCOV_EXCL_LINE
        return t;
    } // LCOV_EXCL_LINE

    time_t to_unix(roref in)
    {
        ::tm t { 0 };
        if (ASN1_TIME_to_tm(in.get(), &t) != 1)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to parse ASN1_TIME to tm struct."); // LCOV_EXCL_LINE
        return timegm(&t);
    } // LCOV_EXCL_LINE

    void set_offset(rwref t, std::chrono::seconds const& from_now)
    {
        if (X509_time_adj_ex(t.get(), 0, from_now.count(), nullptr) == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to update ASN1_TIME offset."); // LCOV_EXCL_LINE
    } // LCOV_EXCL_LINE

    void set_unix(rwref t, time_t const& unixts)
    {
        time_t tmp = unixts;
        if (X509_time_adj_ex(t.get(), 0, 0, &tmp) == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to update ASN1_TIME from unix timestamp."); // LCOV_EXCL_LINE
    } // LCOV_EXCL_LINE

} // namespace asn1_time
} // namespace ossl
