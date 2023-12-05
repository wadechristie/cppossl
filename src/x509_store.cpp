//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/x509_store.hpp"
#include "cppossl/error.hpp"

namespace ossl {
namespace x509_store {

    owned<::X509_STORE> retain(roref store)
    {
        X509_STORE_up_ref(const_cast<::X509_STORE*>(store.get()));
        return owned<::X509_STORE> { const_cast<::X509_STORE*>(store.get()) };
    }

    void set_flags(rwref store, int flags)
    {
        if (!X509_STORE_set_flags(store.get(), flags))
            CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to set new OpenSSL X509_STORE flags."); // LCOV_EXCL_LINE
    }

    void set_depth(rwref store, int depth)
    {
        if (!X509_STORE_set_depth(store.get(), depth))
            CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to set new OpenSSL X509_STORE depth."); // LCOV_EXCL_LINE
    }

    void add(rwref store, x509::roref x509)
    {
        if (!X509_STORE_add_cert(store.get(), const_cast<::X509*>(x509.get())))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to add X.509 certificate to X.509 store."); // LCOV_EXCL_LINE
    }

    void add(rwref store, x509_crl::roref crl)
    {
        if (!X509_STORE_add_crl(store.get(), const_cast<::X509_CRL*>(crl.get())))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Failed to add X.509 certificate revocation list to X.509 store.");
    }

} // namespace x509_store
} // namespace ossl
