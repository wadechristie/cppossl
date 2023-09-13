//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <chrono>

#include <cppossl/raii.hpp>

namespace ossl {
namespace asn1_time {

    /**
     * \defgroup asn1_time OpenSSL ASN1_TIME
     */
    /**@{*/

    owned<::ASN1_TIME> now();
    owned<::ASN1_TIME> offset(std::chrono::seconds const& from_now);
    owned<::ASN1_TIME> from_unix(time_t const& unixts);

    void set_offset(::ASN1_TIME* t, std::chrono::seconds const& from_now);

    inline void set_offset(owned<::ASN1_TIME> const& t, std::chrono::seconds const& from_now)
    {
        set_offset(t.get(), from_now);
    }

    void set_unix(::ASN1_TIME* time, time_t const& unixts);

    inline void set_unix(owned<::ASN1_TIME> const& t, time_t const& unixts)
    {
        set_unix(t.get(), unixts);
    }

    /**@}*/

} // namespace asn1_time
} // namespace ossl
