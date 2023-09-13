//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string>
#include <string_view>

#include <cppossl/bio.hpp>
#include <cppossl/evp_pkey.hpp>
#include <cppossl/raii.hpp>

namespace ossl {
namespace x509_req {

    /**
     * \defgroup x509_req OpenSSL X509_REQ
     */
    /**@{*/

    using roref = raii::roref<::X509_REQ>;
    using rwref = raii::rwref<::X509_REQ>;

    /** @brief Return the X.509 parsed subject principal. */
    owned<::X509_NAME> get_subject(roref req);

    /** @brief Return true if the given private key matches the given X.509 certificate request. */
    bool check_key(roref req, evp_pkey::roref pkey);

    /** @brief Print X.509 certificate request text to a string. */
    std::string print_text(roref req);

    /** @brief Print X.509 certificate request text to an OpenSSL BIO. */
    void print_text(bio const& bio, roref req);

    /**@}*/

} // namespace x509_req
} // namespace ossl
