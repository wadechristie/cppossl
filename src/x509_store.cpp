//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/x509_store.hpp"
#include "cppossl/error.hpp"

namespace ossl {

x509_store_t new_ref(x509_store_t const& store)
{
    X509_STORE_up_ref(store.get());
    return x509_store_t { store.get() };
}

/******************************************************************************
 *
 * x509_store
 *
 ******************************************************************************/

x509_store::x509_store()
    : _store(x509_store_t::make())
{
    set_flags(X509_V_FLAG_X509_STRICT);
}

x509_store::x509_store(int flags)
    : _store(x509_store_t::make())
{
    set_flags(flags);
}

x509_store::x509_store(x509_store const& copy)
    : _store(new_ref(copy._store))
{
}

x509_store& x509_store::operator=(x509_store const& copy)
{
    if (this != &copy)
        _store = new_ref(copy._store);
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

x509_store& x509_store::add(x509_t const& x509)
{
    if (!X509_STORE_add_cert(_store.get(), x509.get()))
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to add X.509 certificate to X.509 store."); // LCOV_EXCL_LINE
    return *this;
}

x509_store& x509_store::add(x509_crl_t const& crl)
{
    if (!X509_STORE_add_crl(_store.get(), crl.get()))
        CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
            "Failed to add X.509 certificate revocation list to X.509 store.");

    return *this;
}

} // namespace ossl
