//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <array>

#include "cppossl/error.hpp"
#include "cppossl/general_name.hpp"
#include "cppossl/raii.hpp"

namespace ossl {

namespace _ {

    static general_name_t make_ia5_general_name(int type, std::string_view const& name)
    {
        asn1_ia5string_t ia5 { ASN1_IA5STRING_new() };
        if (ia5 == nullptr)
            CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to allocate new OpenSSL ASN1_IA5STRING object."); // LCOV_EXCL_LINE

        if (!ASN1_STRING_set(ia5.get(), name.data(), name.size()))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set alternate name IA5 value."); // LCOV_EXCL_LINE

        general_name_t genname = general_name_t::make();
        GENERAL_NAME_set0_value(genname.get(), type, ia5.release());

        return genname;
    }

} // _ namespace

general_name_t make_dns_general_name(std::string_view const& dns)
{
    return _::make_ia5_general_name(GEN_DNS, dns);
}

general_name_t make_email_general_name(std::string_view const& email)
{
    return _::make_ia5_general_name(GEN_EMAIL, email);
}

general_name_t make_uri_general_name(std::string_view const& uri)
{
    return _::make_ia5_general_name(GEN_URI, uri);
}

general_name_t make_ip_general_name(std::string const& ipstr)
{
    asn1_octect_string_t octstr { a2i_IPADDRESS(ipstr.c_str()) };
    if (octstr == nullptr)
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to convert IP address string to OpenSSL ASN1_OCTET_STRING object.");

    general_name_t genname = general_name_t::make();
    GENERAL_NAME_set0_value(genname.get(), GEN_IPADD, octstr.release());

    return genname;
}

general_name_t make_ip_general_name(::in_addr const& ipv4)
{
    std::array<char, INET_ADDRSTRLEN> buffer { 0 };

    if (inet_ntop(AF_INET, &ipv4, buffer.data(), buffer.size()) == nullptr)
        CPPOSSL_THROW_ERRNO(EINVAL, "Failed to convert IPv4 address to string."); // LCOV_EXCL_LINE

    auto const ipstr = std::string(buffer.data());
    return make_ip_general_name(ipstr);
}

general_name_t make_ip_general_name(::in6_addr const& ipv6)
{
    std::array<char, INET6_ADDRSTRLEN> buffer { 0 };

    if (inet_ntop(AF_INET6, &ipv6, buffer.data(), buffer.size()) == nullptr)
        CPPOSSL_THROW_ERRNO(EINVAL, "Failed to convert IPv6 address to string."); // LCOV_EXCL_LINE

    auto const ipstr = std::string(buffer.data());
    return make_ip_general_name(ipstr);
}

} // namespace ossl
