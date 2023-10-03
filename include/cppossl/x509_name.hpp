//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <functional>
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

    /** @brief X509_NAME readonly reference.*/
    using roref = raii::roref<::X509_NAME>;

    /** @brief X509_NAME read/write reference.*/
    using rwref = raii::rwref<::X509_NAME>;

    /**
     * @brief Compare to X509_NAME objects.  Returns -1, 0, or 1 is object a is
     * less than, equals, or is greater than object b.
     *
     * @throws ossl::openssl_error
     */
    int cmp(roref left, roref right);

    /** @brief Determine is two X509_NAME objects are equal. */
    inline bool equal(roref left, roref right)
    {
        return cmp(left, right) == 0;
    }

    /** @brief Print X509_NAME text to a c++ string. */
    std::string print_text(roref name);

    /**
     * @brief Print X509_NAME text to a c++ string.
     *
     * @see X509_NAME_print_ex()
     */
    std::string print_text(roref name, int flags);

    /** @brief Print X509_NAME text to the given BIO object. */
    void print_text(bio const& bio, roref name);

    /**
     * @brief Print X509_NAME text to the given BIO object.
     *
     * @see X509_NAME_print_ex()
     */
    void print_text(bio const& bio, roref name, int flags);

    /** @brief Attempt to parse an X509_NAME from the given string. */
    owned<::X509_NAME> parse(std::string const& str);

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

    owned<::X509_NAME> build(std::function<void(owned<::X509_NAME>&)> callback);

    /**@}*/

} // namespace x509_name
} // namespace ossl
