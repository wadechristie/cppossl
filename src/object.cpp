//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/object.hpp"
#include "cppossl/error.hpp"

namespace ossl {
namespace object {

    nid nid::make(int id)
    {
        return nid(id);
    }

    nid::nid(int id)
    {
        ::ASN1_OBJECT* obj = OBJ_nid2obj(id);
        if (obj == nullptr)
        {
            CPPOSSL_THROW_ERRNO(EINVAL, "Invalid object NID.");
        }

        _nid = id;
    }

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
