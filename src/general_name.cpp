//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <array>

#include "cppossl/error.hpp"
#include "cppossl/general_name.hpp"
#include "cppossl/raii.hpp"

namespace ossl {
namespace general_name {

    namespace _ {

        static owned<::GENERAL_NAME> make_ia5(int type, std::string_view const& name)
        {
            auto ia5str = make<::ASN1_IA5STRING>();
            if (!ASN1_STRING_set(ia5str.get(), name.data(), name.size()))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set alternate name IA5 value."); // LCOV_EXCL_LINE

            owned<::GENERAL_NAME> genname = make<::GENERAL_NAME>();
            GENERAL_NAME_set0_value(genname.get(), type, ia5str.release());

            return genname;
        }

    } // _ namespace

    owned<::GENERAL_NAME> copy(roref name)
    {
        return owned<::GENERAL_NAME> { GENERAL_NAME_dup(name.get()) };
    }

    owned<::GENERAL_NAME> make_dns(std::string_view const& dns)
    {
        return _::make_ia5(GEN_DNS, dns);
    }

    owned<::GENERAL_NAME> make_email(std::string_view const& email)
    {
        return _::make_ia5(GEN_EMAIL, email);
    }

    owned<::GENERAL_NAME> make_uri(std::string_view const& uri)
    {
        return _::make_ia5(GEN_URI, uri);
    }

    owned<::GENERAL_NAME> make_ip(std::string const& ipstr)
    {
        owned<::ASN1_OCTET_STRING> octstr { a2i_IPADDRESS(ipstr.c_str()) };
        if (octstr == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR(
                "Failed to convert IP address string to OpenSSL ASN1_OCTET_STRING object.");

        owned<::GENERAL_NAME> genname = owned<::GENERAL_NAME>::make();
        GENERAL_NAME_set0_value(genname.get(), GEN_IPADD, octstr.release());

        return genname;
    }

    owned<::GENERAL_NAME> make_ip(::in_addr const& ipv4)
    {
        std::array<char, INET_ADDRSTRLEN> buffer { 0 };

        if (inet_ntop(AF_INET, &ipv4, buffer.data(), buffer.size()) == nullptr)
            CPPOSSL_THROW_ERRNO(EINVAL, "Failed to convert IPv4 address to string."); // LCOV_EXCL_LINE

        auto const ipstr = std::string(buffer.data());
        return make_ip(ipstr);
    }

    owned<::GENERAL_NAME> make_ip(::in6_addr const& ipv6)
    {
        std::array<char, INET6_ADDRSTRLEN> buffer { 0 };

        if (inet_ntop(AF_INET6, &ipv6, buffer.data(), buffer.size()) == nullptr)
            CPPOSSL_THROW_ERRNO(EINVAL, "Failed to convert IPv6 address to string."); // LCOV_EXCL_LINE

        auto const ipstr = std::string(buffer.data());
        return make_ip(ipstr);
    }

} // namespace general_name
} // namespace ossl
