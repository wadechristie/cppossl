//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <openssl/pem.h>

#include "cppossl/bio.hpp"
#include "cppossl/error.hpp"
#include "cppossl/x509_req.hpp"

namespace ossl {
namespace x509_req {

    namespace _ {

        static void bio_print_text(bio const& bio, roref req)
        {
            if (X509_REQ_print_ex(bio, const_cast<X509_REQ*>(req.get()), 0, 0) <= 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to print X.509 request object to text."); // LCOV_EXCL_LINE
        } // LCOV_EXCL_LINE

    } // _ namespace

    void print_text(bio const& bio, roref req)
    {
        _::bio_print_text(bio, req);
    }

    std::string print_text(roref req)
    {
        buffered_bio bio;
        print_text(bio, req);
        return bio.str();
    }

    bool check_key(roref req, evp_pkey::roref pkey)
    {
        CPPOSSL_ASSERT(req.get() != nullptr);
        CPPOSSL_ASSERT(pkey.get() != nullptr);
        return X509_REQ_check_private_key(const_cast<X509_REQ*>(req.get()), const_cast<EVP_PKEY*>(pkey.get())) == 1;
    }

    owned<::X509_NAME> get_subject(roref req)
    {
        return owned<::X509_NAME> { X509_NAME_dup(X509_REQ_get_subject_name(req.get())) };
    }

} // namespace x509_req
} // namespace ossl
