//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/object.hpp"
#include "cppossl/error.hpp"

namespace ossl {
namespace object {

    namespace _ {
#define _CASE(NAME) static nid const NAME(wellknown_nid::NAME);
        WELLKNOWN_NID_TABLE(_CASE)
#undef _CASE
    }

    nid nid::make(int id)
    {
        ::ASN1_OBJECT* obj = OBJ_nid2obj(id);
        if (obj == nullptr)
        {
            CPPOSSL_THROW_ERRNO(EINVAL, "Invalid object NID.");
        }

        return nid(id);
    }

    nid nid::from_object(::ASN1_OBJECT const* obj)

    {
        return nid(OBJ_obj2nid(obj));
    }

#define _CASE(NAME)        \
    nid const& nid::NAME() \
    {                      \
        return _::NAME;    \
    }
    WELLKNOWN_NID_TABLE(_CASE)
#undef _CASE

    std::string_view short_name(nid const& id)
    {
        return OBJ_nid2sn(id);
    }

    std::string_view long_name(nid const& id)
    {
        return OBJ_nid2ln(id);
    }

} // namespace object
} // namespace ossl
