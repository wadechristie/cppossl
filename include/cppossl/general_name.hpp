//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <arpa/inet.h>

#include <string_view>

#include <cppossl/raii.hpp>

namespace ossl {

/**
 * \defgroup general_name OpenSSL GENERAL_NAME
 */
/**@{*/

/** @brief Convert a string to OpenSSL DNS GENERAL_NAME object. */
owned<::GENERAL_NAME> make_dns_general_name(std::string_view const& dns);

/** @brief Convert a string to OpenSSL email GENERAL_NAME object. */
owned<::GENERAL_NAME> make_email_general_name(std::string_view const& email);

/** @brief Convert a string to OpenSSL URI GENERAL_NAME object. */
owned<::GENERAL_NAME> make_uri_general_name(std::string_view const& uri);

/** @brief Convert IP address string to OpenSSL GENERAL_NAME object. */
owned<::GENERAL_NAME> make_ip_general_name(std::string const& ipstr);

/** @brief Convert IPv4 address to OpenSSL GENERAL_NAME object. */
owned<::GENERAL_NAME> make_ip_general_name(::in_addr const& ipv4);

/** @brief Convert IPv6 address to OpenSSL GENERAL_NAME object. */
owned<::GENERAL_NAME> make_ip_general_name(::in6_addr const& ipv6);

/**@}*/

} // namespace ossl
