//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cppossl/raii.hpp>
#include <cppossl/x509.hpp>

namespace ossl {
namespace x509_extension {

    owned<::X509_EXTENSION> make_basic_constaints(bool ca, int pathlen = -1);

    owned<::X509_EXTENSION> make_basic_constaints(std::string_view const& confstr);

    owned<::X509_EXTENSION> make_key_usage(std::string_view const& confstr, bool critical);

    owned<::X509_EXTENSION> make_ext_key_usage(std::string_view const& confstr, bool critical);

    owned<::X509_EXTENSION> make_subject_alt_names(raii::roref<STACK_OF(GENERAL_NAME)> altnames);

    owned<::X509_EXTENSION> make_authority_key_id(ossl::x509::roref cacert);

    owned<::X509_EXTENSION> make_crl_distribution_point(raii::roref<STACK_OF(DIST_POINT)> crldists);

    owned<::X509_EXTENSION> make_authority_access_info(std::string_view const& accessinfo);

} // namespace x509_extension
} // namespace ossl
