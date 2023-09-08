//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <string>
#include <string_view>

#include <cppossl/raii.hpp>

namespace ossl {
namespace pem {

    /**
     * \defgroup pem OpenSSL PEM
     */
    /**@{*/

    void to_pem(::BIO* bio, ::X509 const* x509);

    inline void to_pem(bio_t const& bio, x509_t const& x509)
    {
        to_pem(bio.get(), x509.get());
    }

    /** @brief Convert the OpenSSL X.509 certificate object to a PEM string. */
    std::string to_pem_string(::X509 const* x509);

    /** @brief Convert the OpenSSL X.509 certificate object to a PEM string. */
    inline std::string to_pem_string(x509_t const& x509)
    {
        return to_pem_string(x509.get());
    }

    void to_pem(::BIO* bio, ::X509_CRL const* crl);

    inline void to_pem(bio_t const& bio, x509_crl_t const& crl)
    {
        to_pem(bio.get(), crl.get());
    }

    /** @brief Convert the OpenSSL X.509 certificate revocation list object to a PEM string. */
    std::string to_pem_string(::X509_CRL const* crl);

    /** @brief Convert the OpenSSL X.509 certificate revocation list object to a PEM string. */
    inline std::string to_pem_string(x509_crl_t const& crl)
    {
        return to_pem_string(crl.get());
    }

    void to_pem(::BIO* bio, ::X509_REQ const* req);

    inline void to_pem(bio_t const& bio, x509_req_t const& req)
    {
        to_pem(bio.get(), req.get());
    }

    /** @brief Convert the OpenSSL X.509 certificate request object to a PEM string. */
    std::string to_pem_string(::X509_REQ const* req);

    /** @brief Convert the OpenSSL X.509 certificate request object to a PEM string. */
    inline std::string to_pem_string(x509_req_t const& req)
    {
        return to_pem_string(req.get());
    }

    void to_pem(::BIO* bio, ::EVP_PKEY const* pkey);

    void to_pem(::BIO* bio, ::EVP_PKEY const* pkey, std::string_view const& password);

    inline void to_pem(bio_t const& bio, evp_pkey_t const& pkey)
    {
        to_pem(bio.get(), pkey.get());
    }

    inline void to_pem(bio_t const& bio, evp_pkey_t const& pkey, std::string_view const& password)
    {
        to_pem(bio.get(), pkey.get(), password);
    }

    /** @brief Convert the OpenSSL private key object to a PEM string. */
    std::string to_pem_string(::EVP_PKEY const* pkey);

    /** @brief Convert the OpenSSL private key object to a PEM string. */
    std::string to_pem_string(::EVP_PKEY const* pkey, std::string_view const& password);

    /** @brief Convert the OpenSSL private key object to a PEM string. */
    inline std::string to_pem_string(evp_pkey_t const& pkey)
    {
        return to_pem_string(pkey.get());
    }

    /** @brief Convert the OpenSSL private key object to a PEM string. */
    inline std::string to_pem_string(evp_pkey_t const& pkey, std::string_view const& password)
    {
        return to_pem_string(pkey.get(), password);
    }

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
    struct loader<x509_t>
    {
        static x509_t load(std::string_view const& pem);
    };

    /** @brief Load PEM encoded X.509 certificate revocation list. */
    template <>
    struct loader<x509_crl_t>
    {
        static x509_crl_t load(std::string_view const& pem);
    };

    /** @brief Load PEM encoded X.509 certificate request. */
    template <>
    struct loader<x509_req_t>
    {
        static x509_req_t load(std::string_view const& pem);
    };

    /** @brief Load PEM encoded private key. */
    template <>
    struct loader<evp_pkey_t>
    {
        static evp_pkey_t load(std::string_view const& pem);
        static evp_pkey_t load(std::string_view const& pem, std::string_view const& password);
    };

    template <typename T, typename... ArgsT>
    T load(ArgsT&&... args)
    {
        return loader<T>::load(std::forward<ArgsT>(args)...);
    }

    /**@}*/

} // namespace pem
} // namespace ossl
