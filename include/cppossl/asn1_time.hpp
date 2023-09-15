//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <chrono>
#include <ctime>

#include <cppossl/raii.hpp>

namespace ossl {
namespace asn1_time {

    /**
     * \defgroup asn1_time OpenSSL ASN1_TIME
     */
    /**@{*/

    using roref = raii::roref<::ASN1_TIME>;
    using rwref = raii::rwref<::ASN1_TIME>;

    owned<::ASN1_TIME> now();
    owned<::ASN1_TIME> offset(std::chrono::seconds const& from_now);

    owned<::ASN1_TIME> from_unix(time_t const& unixts);
    time_t to_unix(roref time);

    void set_offset(rwref time, std::chrono::seconds const& from_now);

    void set_unix(rwref time, time_t const& unixts);

    /**@}*/

} // namespace asn1_time
} // namespace ossl
