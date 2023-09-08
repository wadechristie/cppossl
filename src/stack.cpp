//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/stack.hpp"
#include "cppossl/error.hpp"

namespace ossl {

void push(dist_point_sk_t const& dpoints, dist_point_t dpoint)
{
    if (!sk_DIST_POINT_push(dpoints.get(), dpoint.get()))
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to push distribution point onto DIST_POINT stack."); // LCOV_EXCL_LINE
    dpoint.release();
}

void push(general_name_sk_t const& names, general_name_t name)
{
    if (!sk_GENERAL_NAME_push(names.get(), name.get()))
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to push name onto GENERAL_NAME stack."); // LCOV_EXCL_LINE
    name.release();
}

void push(x509_crl_sk_t const& crls, x509_crl_t crl)
{
    if (!sk_X509_CRL_push(crls.get(), crl.get()))
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to push name onto X509_CRL stack."); // LCOV_EXCL_LINE
    crl.release();
}

void push(x509_extension_sk_t const& exts, x509_extension_t ext)
{
    if (!sk_X509_EXTENSION_push(exts.get(), ext.get()))
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to push extension onto X509_EXTENSION stack."); // LCOV_EXCL_LINE
    ext.release();
}

} // namespace ossl
