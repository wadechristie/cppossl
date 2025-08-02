//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <array>

#include "cppossl/x509_subject_alt_name.hpp"

namespace ossl {
namespace x509 {

    saltname saltname::dns(std::string_view const& dns)
    {
        return saltname(DNS, general_name::make_dns(dns));
    }

    saltname saltname::email(std::string_view const& email)
    {
        return saltname(EMAIL, general_name::make_email(email));
    }

    saltname saltname::uri(std::string_view const& uri)
    {
        return saltname(URI, general_name::make_uri(uri));
    }

    saltname saltname::ip(std::string const& ipstr)
    {
        return saltname(IP, general_name::make_ip(ipstr));
    }

    saltname saltname::ip(::in_addr const& ipv4)
    {
        return saltname(IP, general_name::make_ip(ipv4));
    }

    saltname saltname::ip(::in6_addr const& ipv6)
    {
        return saltname(IP, general_name::make_ip(ipv6));
    }

    saltname saltname::upn(std::string_view const& upn)
    {
        return saltname(UPN, general_name::make_upn(upn));
    }

    saltname::saltname(type t, owned<::GENERAL_NAME> name)
        : _type(t)
        , _name(std::move(name))
    {
    }

} // namespace x509
} // namespace ossl
