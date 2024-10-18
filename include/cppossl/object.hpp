//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string_view>

#include <openssl/objects.h>

namespace ossl {
namespace object {

    enum class wellknown_nid : int
    {
        key_usage = NID_key_usage,
        subject_alt_name = NID_subject_alt_name,
        basic_constraints = NID_basic_constraints,
        authority_key_identifier = NID_authority_key_identifier,
        crl_distribution_points = NID_crl_distribution_points,
        ext_key_usage = NID_ext_key_usage,
        info_access = NID_info_access,
    };

    class nid
    {
    public:
        static nid make(int id);

        inline nid(wellknown_nid id)
        {
            _nid = static_cast<std::underlying_type_t<wellknown_nid>>(id);
        }

        nid(nid&&) = delete;
        nid& operator=(nid&&) = delete;

        nid(nid const&) = default;
        nid& operator=(nid const&) = default;

        ~nid()
        {
            _nid = -1;
        }

        inline operator int()
        {
            return _nid;
        }

        inline operator int() const
        {
            return _nid;
        }

    private:
        explicit nid(int id);

        int _nid { NID_undef };
    };

    std::string_view short_name(nid const& id);
    std::string_view long_name(nid const& id);

} // namespace object
} // namespace ossl
