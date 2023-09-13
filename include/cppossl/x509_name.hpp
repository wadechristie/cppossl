//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <cppossl/bio.hpp>
#include <cppossl/raii.hpp>

namespace ossl {
namespace x509_name {

    /**
     * \defgroup x509_name OpenSSL X509_NAME
     */
    /**@{*/

    using roref = raii::roref<::X509_NAME>;
    using rwref = raii::rwref<::X509_NAME>;

    std::string print_text(roref name);

    void print_text(bio const& bio, roref name);

    owned<::X509_NAME> parse_name(std::string_view const& str);

    /**
     * @brief Get X509_NAME common name.
     */
    std::string get_common_name(roref name);

    /**
     * @brief Set X509_NAME common name.
     *
     * @throws ossl::openssl_error
     */
    void set_common_name(rwref name, std::string_view const& value);

    /**
     * @brief Get X509_NAME locality.
     */
    std::string get_locality(roref name);

    /**
     * @brief Set X509_NAME locality.
     *
     * @throws ossl::openssl_error
     */
    void set_locality(rwref name, std::string_view const& value);

    /**
     * @brief Get X509_NAME state/province.
     */
    std::string get_state(roref name);

    /**
     * @brief Set X509_NAME state/province.
     *
     * @throws ossl::openssl_error
     */
    void set_state(rwref name, std::string_view const& value);

    /**
     * @brief Get X509_NAME state/province.
     */
    inline std::string get_province(roref name)
    {
        return get_state(name);
    }

    /**
     * @brief Set X509_NAME state/province.
     *
     * @throws ossl::openssl_error
     */
    inline void set_province(rwref name, std::string_view const& value)
    {
        set_state(name, value);
    }

    /**
     * @brief Set X509_NAME country.
     */
    std::string get_country(roref name);

    /**
     * @brief Set X509_NAME country.
     *
     * @throws ossl::openssl_error
     */
    void set_country(rwref name, std::string_view const& value);

    /**
     * @brief Get X509_NAME street address.
     */
    std::vector<std::string> get_street_address(roref name);

    /**
     * @brief Set X509_NAME street address.
     *
     * @throws ossl::openssl_error
     */
    void set_street_address(rwref name, std::vector<std::string> const& value);

    /**
     * @brief Get X509_NAME organization names.
     */
    std::vector<std::string> get_organization_name(roref name);

    /**
     * @brief Set X509_NAME organization names.
     *
     * @throws ossl::openssl_error
     */
    void set_organization_name(rwref name, std::vector<std::string> const& value);

    /**
     * @brief Get X509_NAME organization unit names.
     */
    std::vector<std::string> get_organization_unit_name(roref name);

    /**
     * @brief Set X509_NAME organization unit names.
     *
     * @throws ossl::openssl_error
     */
    void set_organization_unit_name(rwref name, std::vector<std::string> const& value);

    /**
     * @brief Get X509_NAME domain components.
     */
    std::vector<std::string> get_domain_components(roref name);

    /**
     * @brief Set X509_NAME domain components.
     *
     * @throws ossl::openssl_error
     */
    void set_domain_components(rwref name, std::vector<std::string> const& value);

    /**@}*/

} // namespace x509_name
} // namespace ossl
