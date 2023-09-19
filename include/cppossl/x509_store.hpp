//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cppossl/raii.hpp>
#include <cppossl/x509.hpp>
#include <cppossl/x509_crl.hpp>

namespace ossl {
namespace x509_store {

    /**
     * \defgroup x509_store OpenSSL X509_STORE
     */
    /**@{*/

    /** @brief X509_STORE readonly reference.*/
    using roref = raii::roref<::X509_STORE>;

    /** @brief X509_STORE readwrite reference.*/
    using rwref = raii::rwref<::X509_STORE>;

    owned<::X509_STORE> retain(roref store);

    void set_flags(rwref store, int flags);

    void set_depth(rwref store, int depth);

    void add(rwref store, x509::roref cert);

    void add(rwref store, x509_crl::roref crl);

    /**@}*/

} // namespace x509_store
} // namespace ossl
