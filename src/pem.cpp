//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <tuple>

#include <openssl/pem.h>

#include "cppossl/bio.hpp"
#include "cppossl/error.hpp"
#include "cppossl/pem.hpp"

namespace ossl {
namespace pem {

    namespace _ {

        static x509_t load_x509_bio(bio const& bio)
        {
            ::X509* tmp = nullptr;
            if (PEM_read_bio_X509(bio, &tmp, nullptr, nullptr) == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to load X.509 certificate revocation list PEM.");
            return x509_t { tmp };
        }

        static x509_crl_t load_x509_crl_bio(bio const& bio)
        {
            ::X509_CRL* tmp = nullptr;
            if (PEM_read_bio_X509_CRL(bio, &tmp, nullptr, nullptr) == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to load X.509 certificate revocation list PEM.");
            return x509_crl_t { tmp };
        }

        static x509_req_t load_x509_req_bio(bio const& bio)
        {
            ::X509_REQ* tmp = nullptr;
            if (PEM_read_bio_X509_REQ(bio, &tmp, nullptr, nullptr) == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to load X.509 certificate request PEM.");
            return x509_req_t { tmp };
        }

        using password_tuple = std::tuple<void const*, size_t>;

        /**
         * @param[in] buf A buffer to write the passphrase.
         * @param[in] size The maximum length of the passphrase.
         * @param[in] rwflag A flag which is set to 0 when reading and 1 when writing.
         */
        static int pkey_password_cb(char* buf, int size, int rwflag, void* u)
        {
            password_tuple const* password = reinterpret_cast<password_tuple const*>(u);
            if (password == nullptr)
                return -1;

            auto const& [pass, passlen] = *password;
            CPPOSSL_ASSERT(size >= 0);
            if (pass == nullptr || passlen == 0 || static_cast<size_t>(size) <= passlen)
                return -1;

            memcpy(buf, pass, passlen);
            buf[passlen] = '\0';
            return passlen;
        }

        static evp_pkey_t load_pkey_bio(bio const& bio, void const* pass, size_t const passlen)
        {
            EVP_PKEY* key = nullptr;
            password_tuple password { pass, passlen };
            if (PEM_read_bio_PrivateKey(bio, &key, pkey_password_cb, &password) == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to load private key PEM.");
            return evp_pkey_t { key };
        }

        static void pkey_write_bio(bio const& bio, ::EVP_PKEY const* key, void const* pass, size_t passlen)
        {
            if (PEM_write_bio_PrivateKey(bio,
                    key,
                    /*enc=*/(pass != nullptr ? EVP_aes_256_cbc() : 0),
                    /*kstr=*/reinterpret_cast<uint8_t const*>(pass),
                    /*klen=*/passlen,
                    /*cb=*/nullptr,
                    /*u=*/nullptr)
                == 0) {
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to write private key PEM."); // LCOV_EXCL_LINE
            }
        }

        static void x509_write_bio(bio const& bio, ::X509 const* x509)
        {
            if (PEM_write_bio_X509(bio, x509) == 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to write X.509 PEM."); // LCOV_EXCL_LINE
        }

        static void x509_crl_write_bio(bio const& bio, ::X509_CRL const* crl)
        {
            if (PEM_write_bio_X509_CRL(bio, crl) == 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to write X.509 revocation list PEM."); // LCOV_EXCL_LINE
        }

        static void x509_req_write_bio(bio const& bio, ::X509_REQ const* req)
        {
            if (PEM_write_bio_X509_REQ(bio, req) == 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to write X.509 request PEM."); // LCOV_EXCL_LINE
        }

    }

    std::string to_pem_string(::EVP_PKEY const* pkey)
    {
        buffered_bio bio;
        _::pkey_write_bio(bio, pkey, nullptr, 0);
        return bio.str();
    }

    std::string to_pem_string(::EVP_PKEY const* pkey, std::string_view const& password)
    {
        buffered_bio bio;
        _::pkey_write_bio(bio, pkey, password.data(), password.size());
        return bio.str();
    }

    std::string to_pem_string(::X509 const* x509)
    {
        buffered_bio bio;
        _::x509_write_bio(bio, x509);
        return bio.str();
    }

    std::string to_pem_string(::X509_CRL const* crl)
    {
        buffered_bio bio;
        _::x509_crl_write_bio(bio, crl);
        return bio.str();
    }

    std::string to_pem_string(::X509_REQ const* req)
    {
        buffered_bio bio;
        _::x509_req_write_bio(bio, req);
        return bio.str();
    }

    x509_t loader<x509_t>::load(std::string_view const& pem)
    {
        auto const bio = bio::from_string(pem);
        return _::load_x509_bio(bio);
    }

    x509_crl_t loader<x509_crl_t>::load(std::string_view const& pem)
    {
        auto const bio = bio::from_string(pem);
        return _::load_x509_crl_bio(bio);
    }

    x509_req_t loader<x509_req_t>::load(std::string_view const& pem)
    {
        auto const bio = bio::from_string(pem);
        return _::load_x509_req_bio(bio);
    }

    evp_pkey_t loader<evp_pkey_t>::load(std::string_view const& pem)
    {
        auto bio = bio::from_string(pem);
        return _::load_pkey_bio(bio, nullptr, 0);
    }

    evp_pkey_t loader<evp_pkey_t>::load(std::string_view const& pem, std::string_view const& password)
    {
        auto bio = bio::from_string(pem);
        return _::load_pkey_bio(bio, password.data(), password.size());
    }

} // namespace pem
} // namespace ossl
