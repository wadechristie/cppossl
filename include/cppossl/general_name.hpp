//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <arpa/inet.h>

#include <string_view>

#include <cppossl/asn1_string.hpp>
#include <cppossl/raii.hpp>

namespace ossl {
namespace general_name {

    /**
     * \defgroup general_name OpenSSL GENERAL_NAME
     */
    /**@{*/

    /** @brief GENERAL_NAME readonly reference.*/
    using roref = raii::roref<::GENERAL_NAME>;

    /** @brief GENERAL_NAME readwrite reference.*/
    using rwref = raii::rwref<::GENERAL_NAME>;

    owned<::GENERAL_NAME> copy(roref name);

    /** @brief Convert a string to OpenSSL DNS GENERAL_NAME object. */
    owned<::GENERAL_NAME> make_dns(std::string_view const& dns);

    /** @brief Convert a string to OpenSSL email GENERAL_NAME object. */
    owned<::GENERAL_NAME> make_email(std::string_view const& email);

    /** @brief Convert a string to OpenSSL URI GENERAL_NAME object. */
    owned<::GENERAL_NAME> make_uri(std::string_view const& uri);

    /** @brief Convert IP address string to OpenSSL GENERAL_NAME object. */
    owned<::GENERAL_NAME> make_ip(std::string const& ipstr);

    /** @brief Convert IPv4 address to OpenSSL GENERAL_NAME object. */
    owned<::GENERAL_NAME> make_ip(::in_addr const& ipv4);

    /** @brief Convert IPv6 address to OpenSSL GENERAL_NAME object. */
    owned<::GENERAL_NAME> make_ip(::in6_addr const& ipv6);

    owned<::GENERAL_NAME> make_upn(std::string_view const& upn);

    /**@}*/

} // namespace general_name
} // namespace ossl
