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

    asn1_time_t now();
    asn1_time_t offset(std::chrono::seconds const& from_now);
    asn1_time_t from_unix(time_t const& unixts);

    void set_offset(::ASN1_TIME* t, std::chrono::seconds const& from_now);

    inline void set_offset(asn1_time_t const& t, std::chrono::seconds const& from_now)
    {
        set_offset(t.get(), from_now);
    }

    void set_unix(::ASN1_TIME* time, time_t const& unixts);

    inline void set_unix(asn1_time_t const& t, time_t const& unixts)
    {
        set_unix(t.get(), unixts);
    }

    /**@}*/

} // namespace asn1_time
} // namespace ossl
