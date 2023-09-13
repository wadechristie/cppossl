//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <openssl/pem.h>

#include "cppossl/bio.hpp"
#include "cppossl/error.hpp"
#include "cppossl/x509_crl.hpp"

namespace ossl {
namespace x509_crl {

    namespace _ {

        static void x509_crl_print_text(bio const& bio, roref req)
        {
            if (X509_CRL_print_ex(bio, const_cast<X509_CRL*>(req.get()), 0) <= 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to print X.509 CRL object to text."); // LCOV_EXCL_LINE
        } // LCOV_EXCL_LINE

    } // _ namespace

    owned<::X509_CRL> retain(roref crl)
    {
        X509_CRL_up_ref(const_cast<::X509_CRL*>(crl.get()));
        return owned<::X509_CRL> { const_cast<::X509_CRL*>(crl.get()) };
    }

    void print_text(bio const& bio, roref crl)
    {
        _::x509_crl_print_text(bio, crl);
    }

    std::string print_text(roref crl)
    {
        buffered_bio bio;
        print_text(bio, crl);
        return bio.str();
    }

} // namespace x509_crl
} // namespace ossl
