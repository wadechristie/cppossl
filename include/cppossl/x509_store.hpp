//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cppossl/raii.hpp>

namespace ossl {

/**
 * \defgroup x509_store OpenSSL X509_STORE
 */
/**@{*/

/** @brief Retrieve a new reference to the given OpenSSL X509_STORE object. */
x509_store_t new_ref(x509_store_t const& store);

/** @brief C++ utility wrapper around `x509_store_ptr`. */
class x509_store {
public:
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

    x509_store& add(x509_t const& cert);

    x509_store& add(x509_crl_t const& crl);

    inline operator ::X509_STORE*() const
    {
        return _store.get();
    }

private:
    x509_store_t _store;
};

/**@}*/

} // namespace ossl
