//
// Copyright (c) Wade Christie and contributors. All rights reserved.
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

        static owned<::X509> load_x509_bio(bio const& bio)
        {
            ::X509* tmp = nullptr;
            if (PEM_read_bio_X509(bio, &tmp, nullptr, nullptr) == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to load X.509 certificate revocation list PEM.");
            return owned<::X509> { tmp };
        }

        static owned<::X509_CRL> load_x509_crl_bio(bio const& bio)
        {
            ::X509_CRL* tmp = nullptr;
            if (PEM_read_bio_X509_CRL(bio, &tmp, nullptr, nullptr) == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to load X.509 certificate revocation list PEM.");
            return owned<::X509_CRL> { tmp };
        }

        static owned<::X509_REQ> load_x509_req_bio(bio const& bio)
        {
            ::X509_REQ* tmp = nullptr;
            if (PEM_read_bio_X509_REQ(bio, &tmp, nullptr, nullptr) == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to load X.509 certificate request PEM.");
            return owned<::X509_REQ> { tmp };
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

        static owned<::EVP_PKEY> load_pkey_bio(bio const& bio, void const* pass, size_t const passlen)
        {
            owned<::EVP_PKEY> key;
            password_tuple password { pass, passlen };
            if (PEM_read_bio_PrivateKey(bio, key.capture(), pkey_password_cb, &password) == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to load private key PEM.");
            return key;
        }

        static void pkey_write_bio(bio const& bio, evp_pkey::roref key, void const* pass, size_t passlen)
        {
            if (PEM_write_bio_PrivateKey(bio,
                    key.get(),
                    /*enc=*/(pass != nullptr ? EVP_aes_256_cbc() : 0),
                    /*kstr=*/reinterpret_cast<uint8_t const*>(pass),
                    /*klen=*/passlen,
                    /*cb=*/nullptr,
                    /*u=*/nullptr)
                == 0)
            {
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to write private key PEM."); // LCOV_EXCL_LINE
            }
        }

        static void x509_write_bio(bio const& bio, x509::roref x509)
        {
            if (PEM_write_bio_X509(bio, x509.get()) == 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to write X.509 PEM."); // LCOV_EXCL_LINE
        }

        static void x509_crl_write_bio(bio const& bio, x509_crl::roref crl)
        {
            if (PEM_write_bio_X509_CRL(bio, crl.get()) == 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to write X.509 revocation list PEM."); // LCOV_EXCL_LINE
        }

        static void x509_req_write_bio(bio const& bio, x509_req::roref req)
        {
            if (PEM_write_bio_X509_REQ(bio, req.get()) == 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to write X.509 request PEM."); // LCOV_EXCL_LINE
        }

    }

    std::string to_pem_string(evp_pkey::roref pkey)
    {
        buffered_bio bio;
        _::pkey_write_bio(bio, pkey.get(), nullptr, 0);
        return bio.str();
    }

    std::string to_pem_string(evp_pkey::roref pkey, std::string_view const& password)
    {
        buffered_bio bio;
        _::pkey_write_bio(bio, pkey.get(), password.data(), password.size());
        return bio.str();
    }

    std::string to_pem_string(x509::roref x509)
    {
        buffered_bio bio;
        _::x509_write_bio(bio, x509);
        return bio.str();
    }

    std::string to_pem_string(x509_crl::roref crl)
    {
        buffered_bio bio;
        _::x509_crl_write_bio(bio, crl);
        return bio.str();
    }

    std::string to_pem_string(x509_req::roref req)
    {
        buffered_bio bio;
        _::x509_req_write_bio(bio, req);
        return bio.str();
    }

    owned<::X509> loader<::X509>::load(std::string_view const& pem)
    {
        auto const bio = bio::from_string(pem);
        return _::load_x509_bio(bio);
    }

    owned<::X509_CRL> loader<::X509_CRL>::load(std::string_view const& pem)
    {
        auto const bio = bio::from_string(pem);
        return _::load_x509_crl_bio(bio);
    }

    owned<::X509_REQ> loader<::X509_REQ>::load(std::string_view const& pem)
    {
        auto const bio = bio::from_string(pem);
        return _::load_x509_req_bio(bio);
    }

    owned<::EVP_PKEY> loader<::EVP_PKEY>::load(std::string_view const& pem)
    {
        auto bio = bio::from_string(pem);
        return _::load_pkey_bio(bio, nullptr, 0);
    }

    owned<::EVP_PKEY> loader<::EVP_PKEY>::load(std::string_view const& pem, std::string_view const& password)
    {
        auto bio = bio::from_string(pem);
        return _::load_pkey_bio(bio, password.data(), password.size());
    }

} // namespace pem
} // namespace ossl
