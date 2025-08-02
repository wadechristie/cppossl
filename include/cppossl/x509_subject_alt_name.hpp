//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <arpa/inet.h>

#include <string_view>

#include <cppossl/general_name.hpp>
#include <cppossl/raii.hpp>

namespace ossl {
namespace x509 {

    /**
     * @brief Subject Alternative Name
     */
    class saltname
    {
    public:
        enum type
        {
            DNS,
            EMAIL,
            URI,
            IP,
            UPN,
        };

        static saltname dns(std::string_view const& dns);
        static saltname email(std::string_view const& email);
        static saltname uri(std::string_view const& uri);
        static saltname ip(std::string const& ipstr);
        static saltname ip(::in_addr const& ipv4);
        static saltname ip(::in6_addr const& ipv6);
        static saltname upn(std::string_view const& upn);

        saltname(saltname&&) = default;
        saltname& operator=(saltname&&) = default;

        ~saltname() = default;

        inline operator general_name::roref const() const
        {
            return _name;
        }

        inline type get_type() const
        {
            return _type;
        }

    private:
        saltname(type type, owned<::GENERAL_NAME> name);

        saltname(saltname const&) = delete;
        saltname& operator=(saltname const&) = delete;

        type _type;
        owned<::GENERAL_NAME> _name;
    };

} // namespace x509
} // namespace ossl
