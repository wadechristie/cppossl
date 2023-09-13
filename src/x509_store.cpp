//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/x509_store.hpp"
#include "cppossl/error.hpp"

namespace ossl {

/******************************************************************************
 *
 * x509_store
 *
 ******************************************************************************/

owned<::X509_STORE> x509_store::retain(roref store)
{
    X509_STORE_up_ref(const_cast<::X509_STORE*>(store.get()));
    return owned<::X509_STORE> { const_cast<::X509_STORE*>(store.get()) };
}

x509_store::x509_store()
    : _store(make<::X509_STORE>())
{
    set_flags(X509_V_FLAG_X509_STRICT);
}

x509_store::x509_store(int flags)
    : _store(make<::X509_STORE>())
{
    set_flags(flags);
}

x509_store::x509_store(x509_store const& copy)
    : _store(retain(copy._store))
{
}

x509_store& x509_store::operator=(x509_store const& copy)
{
    if (this != &copy)
        _store = retain(copy._store);
    return *this;
}

x509_store& x509_store::set_flags(int flags)
{
    if (!X509_STORE_set_flags(_store.get(), flags))
        CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to set new OpenSSL X509_STORE flags."); // LCOV_EXCL_LINE
    return *this;
}

x509_store& x509_store::set_depth(int depth)
{
    if (!X509_STORE_set_depth(_store.get(), depth))
        CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to set new OpenSSL X509_STORE depth."); // LCOV_EXCL_LINE
    return *this;
}

x509_store& x509_store::add(x509::roref x509)
{
    if (!X509_STORE_add_cert(_store.get(), const_cast<::X509*>(x509.get())))
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to add X.509 certificate to X.509 store."); // LCOV_EXCL_LINE
    return *this;
}

x509_store& x509_store::add(x509_crl::roref crl)
{
    if (!X509_STORE_add_crl(_store.get(), const_cast<::X509_CRL*>(crl.get())))
        CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
            "Failed to add X.509 certificate revocation list to X.509 store.");

    return *this;
}

} // namespace ossl
