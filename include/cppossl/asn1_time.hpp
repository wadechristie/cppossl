//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <chrono>

#include <cppossl/raii.hpp>

namespace ossl {

/**
 * \defgroup asn1_time OpenSSL ASN1_TIME
 */
/**@{*/

asn1_time_t make_asn1_time_now();
asn1_time_t make_asn1_time(std::chrono::seconds const& from_now);
asn1_time_t make_asn1_time(time_t const& unixts);

/**@}*/

} // namespace ossl
