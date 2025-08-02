//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string_view>

#include <openssl/objects.h>

#define WELLKNOWN_NID_TABLE(X)  \
    X(subject_key_identifier)   \
    X(key_usage)                \
    X(subject_alt_name)         \
    X(basic_constraints)        \
    X(authority_key_identifier) \
    X(crl_distribution_points)  \
    X(ext_key_usage)            \
    X(info_access)

namespace ossl {
namespace object {

    enum class wellknown_nid : int
    {
#define _CASE(NAME) NAME = NID_##NAME,
        WELLKNOWN_NID_TABLE(_CASE)
#undef _CASE
    };

    class nid
    {
    public:
        static nid make(int id);

        static nid from_object(::ASN1_OBJECT const* obj);

#define _CASE(NAME) static nid const& NAME();
        WELLKNOWN_NID_TABLE(_CASE)
#undef _CASE

        inline nid(wellknown_nid id)
            : _nid(static_cast<std::underlying_type_t<wellknown_nid>>(id))
        {
        }

        nid(nid&&) = default;
        nid& operator=(nid&&) = default;

        nid(nid const&) = default;
        nid& operator=(nid const&) = default;

        inline ~nid()
        {
        }

        // inline operator int()
        // {
        //     return _nid;
        // }

        inline operator int() const
        {
            return _nid;
        }

        inline bool is_undefined() const
        {
            return _nid <= NID_undef;
        }

    private:
        inline explicit nid(int id)
            : _nid(id)
        {
        }

        int _nid { NID_undef };
    };

    std::string_view short_name(nid const& id);
    std::string_view long_name(nid const& id);

} // namespace object
} // namespace ossl
