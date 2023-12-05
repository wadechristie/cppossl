//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string>
#include <string_view>

#include <cppossl/evp_pkey.hpp>
#include <cppossl/raii.hpp>
#include <cppossl/x509.hpp>
#include <cppossl/x509_crl.hpp>
#include <cppossl/x509_req.hpp>

namespace ossl {
namespace pem {

    /**
     * \defgroup pem OpenSSL PEM
     */
    /**@{*/

    static constexpr std::string_view pem_begin_line_prefix = "-----BEGIN ";
    static constexpr std::string_view pem_end_line_prefix = "-----END ";
    static constexpr std::string_view pem_line_suffix = "-----";

    static constexpr std::string_view encrypted_pkey_begin_line = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    static constexpr std::string_view encrypted_pkey_end_line = "-----END ENCRYPTED PRIVATE KEY-----";

    static constexpr std::string_view pkey_begin_line = "-----BEGIN PRIVATE KEY-----";
    static constexpr std::string_view pkey_end_line = "-----END PRIVATE KEY-----";

    static constexpr std::string_view x509_begin_line = "-----BEGIN CERTIFICATE-----";
    static constexpr std::string_view x509_end_line = "-----END CERTIFICATE-----";

    static constexpr std::string_view x509_crl_begin_line = "-----BEGIN X509 CRL-----";
    static constexpr std::string_view x509_crl_end_line = "-----END X509 CRL-----";

    static constexpr std::string_view x509_req_begin_line = "-----BEGIN CERTIFICATE REQUEST-----";
    static constexpr std::string_view x509_req_end_line = "-----END CERTIFICATE REQUEST-----";

    void to_pem(bio::roref bio, x509::roref x509);

    /** @brief Convert the OpenSSL X.509 certificate object to a PEM string. */
    std::string to_pem_string(x509::roref x509);

    void to_pem(bio::roref bio, x509_crl::roref crl);

    /** @brief Convert the OpenSSL X.509 certificate revocation list object to a PEM string. */
    std::string to_pem_string(x509_crl::roref crl);

    void to_pem(bio::roref bio, x509_req::roref req);

    /** @brief Convert the OpenSSL X.509 certificate request object to a PEM string. */
    std::string to_pem_string(x509_req::roref req);

    void to_pem(bio::roref bio, evp_pkey::roref pkey);

    void to_pem(bio::roref bio, evp_pkey::roref pkey, std::string_view const& password);

    /** @brief Convert the OpenSSL private key object to a PEM string. */
    std::string to_pem_string(evp_pkey::roref pkey);

    /** @brief Convert the OpenSSL private key object to a PEM string. */
    std::string to_pem_string(evp_pkey::roref pkey, std::string_view const& password);

    /** @brief Default PEM load causes a build error. */
    template <typename T>
    struct loader
    {
        static T load(std::string_view const& pem)
        {
            static_assert(sizeof(T) != sizeof(T), "No CPPOSSL decode specialization.");
        }
    };

    /** @brief Load PEM encoded X.509 certificate. */
    template <>
    struct loader<::X509>
    {
        static owned<::X509> load(std::string_view const& pem);
    };

    /** @brief Load PEM encoded X.509 certificate revocation list. */
    template <>
    struct loader<::X509_CRL>
    {
        static owned<::X509_CRL> load(std::string_view const& pem);
    };

    /** @brief Load PEM encoded X.509 certificate request. */
    template <>
    struct loader<::X509_REQ>
    {
        static owned<::X509_REQ> load(std::string_view const& pem);
    };

    /** @brief Load PEM encoded private key. */
    template <>
    struct loader<::EVP_PKEY>
    {
        static owned<::EVP_PKEY> load(std::string_view const& pem);
        static owned<::EVP_PKEY> load(std::string_view const& pem, std::string_view const& password);
    };

    template <typename T, typename... ArgsT>
    auto load(ArgsT&&... args)
    {
        return loader<T>::load(std::forward<ArgsT>(args)...);
    }

    /**@}*/

} // namespace pem
} // namespace ossl
