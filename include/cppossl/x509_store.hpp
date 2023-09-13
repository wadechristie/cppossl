//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cppossl/raii.hpp>
#include <cppossl/x509.hpp>
#include <cppossl/x509_crl.hpp>

namespace ossl {

/**
 * \defgroup x509_store OpenSSL X509_STORE
 */
/**@{*/

/** @brief C++ utility wrapper around `x509_store_ptr`. */
class x509_store
{
public:
    using roref = raii::roref<::X509_STORE>;
    using rwref = raii::rwref<::X509_STORE>;

    /** @brief Retrieve a new reference to the given OpenSSL X509_STORE object. */
    static owned<::X509_STORE> retain(roref store);

    x509_store();

    template <typename IterT>
    x509_store(IterT first, IterT last)
        : x509_store()
    {
        for (auto it = first; it != last; ++it)
            add(*it);
    }

    explicit x509_store(int flags);

    x509_store(x509_store&&) = default;
    x509_store& operator=(x509_store&&) = default;

    x509_store(x509_store const&);
    x509_store& operator=(x509_store const&);

    ~x509_store() = default;

    x509_store& set_flags(int flags);

    x509_store& set_depth(int depth);

    x509_store& add(x509::roref cert);

    x509_store& add(x509_crl::roref crl);

    inline operator ::X509_STORE*() const
    {
        return _store.get();
    }

private:
    owned<::X509_STORE> _store;
};

/**@}*/

} // namespace ossl
