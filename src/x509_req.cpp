//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <openssl/pem.h>

#include "cppossl/bio.hpp"
#include "cppossl/error.hpp"
#include "cppossl/x509_req.hpp"

namespace ossl {

namespace _ {

    static void x509_req_print_text(bio const& bio, ::X509_REQ const* req)
    {
        if (X509_REQ_print_ex(bio, const_cast<X509_REQ*>(req), 0, 0) <= 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to print X.509 request object to text."); // LCOV_EXCL_LINE
    } // LCOV_EXCL_LINE

} // _ namespace

void print_text(bio const& bio, ::X509_REQ const* req)
{
    _::x509_req_print_text(bio, req);
}

std::string print_text(::X509_REQ const* req)
{
    buffered_bio bio;
    print_text(bio, req);
    return bio.str();
}

bool check_key(::X509_REQ const* req, ::EVP_PKEY const* pkey)
{
    CPPOSSL_ASSERT(req != nullptr);
    CPPOSSL_ASSERT(pkey != nullptr);
    return X509_REQ_check_private_key(const_cast<X509_REQ*>(req), const_cast<EVP_PKEY*>(pkey)) == 1;
}

x509_name_t get_subject(::X509_REQ const* req)
{
    return x509_name_t { X509_NAME_dup(X509_REQ_get_subject_name(req)) };
}

} // namespace ossl
