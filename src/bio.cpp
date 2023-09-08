//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <algorithm>
#include <cstring>
#include <sstream>
#include <tuple>
#include <vector>

#include <openssl/evp.h>
#include <openssl/types.h>

#include "cppossl/bio.hpp"
#include "cppossl/error.hpp"

namespace ossl {

namespace _ {

    static std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> derive_key_and_iv(::EVP_CIPHER const* cipher,
        ::EVP_MD const* digest,
        void const* pass,
        size_t const passlen,
        void const* salt,
        size_t const saltlen,
        int const iterations)
    {
        int const cipher_keylen = EVP_CIPHER_key_length(cipher);
        int const cipher_ivlen = EVP_CIPHER_iv_length(cipher);
        std::array<uint8_t, EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH> tmpKeyIv { 0 };

        if (digest == nullptr)
            digest = EVP_sha256();

        const int pbkdf2 = PKCS5_PBKDF2_HMAC(
            /*pass=*/reinterpret_cast<char const*>(pass),
            /*passlen=*/passlen,
            /*salt=*/static_cast<uint8_t const*>(salt),
            /*saltlen=*/saltlen,
            /*iter=*/iterations,
            /*digest=*/digest,
            /*keylen=*/cipher_keylen + cipher_ivlen,
            /*out=*/tmpKeyIv.data());
        if (!pbkdf2)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to dervice key/iv from password.");

        std::array<uint8_t, EVP_MAX_KEY_LENGTH> key { 0 };
        std::array<uint8_t, EVP_MAX_IV_LENGTH> iv { 0 };
        std::copy_n(tmpKeyIv.data(), cipher_keylen, key.data());
        std::copy_n(tmpKeyIv.data() + cipher_keylen, cipher_ivlen, iv.data());

        return std::make_tuple(std::vector<uint8_t> { key.cbegin(), key.cbegin() + cipher_keylen },
            std::vector<uint8_t> { iv.cbegin(), iv.cbegin() + cipher_ivlen });
    }

    static void bio_write(bio const& bio, void const* data, size_t const len)
    {
        if (BIO_write(bio, data, len) != static_cast<int>(len))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to write byte vector to OpenSSL BIO."); // LCOV_EXCL_LINE
    }

} // _ namespace

bio_filter bio_filter::base64()
{
    bio_t bio { BIO_new(BIO_f_base64()) };
    if (bio == nullptr)
        CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to allocate OpenSSL base64 filter BIO."); // LCOV_EXCL_LINE
    return bio_filter { std::move(bio) };
}

bio_filter bio_filter::encryption(
    EVP_CIPHER const* cipher, void const* key, size_t const keylen, void const* iv, size_t const ivlen)
{
    bio_t bio { BIO_new(BIO_f_cipher()) };
    if (bio == nullptr)
        CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to allocate OpenSSL cipher filter BIO."); // LCOV_EXCL_LINE

    auto const required_keylen = EVP_CIPHER_key_length(cipher);
    CPPOSSL_ASSERT(required_keylen >= 0);
    if (keylen < static_cast<size_t>(required_keylen))
        CPPOSSL_THROW_ERRNO(EINVAL, "Cipher key too small.");

    int const required_ivlen = EVP_CIPHER_iv_length(cipher);
    CPPOSSL_ASSERT(required_ivlen >= 0);
    if (ivlen < static_cast<size_t>(required_ivlen))
        CPPOSSL_THROW_ERRNO(EINVAL, "Cipher iv too small.");

    EVP_CIPHER_CTX* cipherCtxRef = nullptr;
    BIO_get_cipher_ctx(bio.get(), &cipherCtxRef);
    if (!EVP_EncryptInit_ex(cipherCtxRef,
            cipher,
            /*engine=*/nullptr,
            static_cast<uint8_t const*>(key),
            static_cast<uint8_t const*>(iv))) {
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to initialize encryption cipher filter BIO."); // LCOV_EXCL_LINE
    }

    return bio_filter { std::move(bio) };
}

bio_filter bio_filter::encryption(::EVP_CIPHER const* cipher, std::string_view const& password, ::EVP_MD const* digest)
{
    auto const& [key, iv] = _::derive_key_and_iv(cipher, digest, password.data(), password.length(), nullptr, 0, 1000);
    return encryption(cipher, key.data(), key.size(), iv.data(), iv.size());
}

bio_filter bio_filter::decryption(
    ::EVP_CIPHER const* cipher, void const* key, size_t const keylen, void const* iv, size_t const ivlen)
{
    bio_t bio { BIO_new(BIO_f_cipher()) };
    if (bio == nullptr)
        CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to allocate cipher filter BIO."); // LCOV_EXCL_LINE

    int const required_keylen = EVP_CIPHER_key_length(cipher);
    CPPOSSL_ASSERT(required_keylen >= 0);
    if (keylen < static_cast<size_t>(required_keylen))
        CPPOSSL_THROW_ERRNO(EINVAL, "Cipher key too small.");

    int const required_ivlen = EVP_CIPHER_iv_length(cipher);
    CPPOSSL_ASSERT(required_ivlen >= 0);
    if (ivlen < static_cast<size_t>(required_ivlen))
        CPPOSSL_THROW_ERRNO(EINVAL, "Cipher iv too small.");

    EVP_CIPHER_CTX* cipherCtxRef = nullptr;
    BIO_get_cipher_ctx(bio.get(), &cipherCtxRef);
    if (!EVP_DecryptInit_ex(cipherCtxRef,
            cipher,
            /*engine=*/nullptr,
            static_cast<uint8_t const*>(key),
            static_cast<uint8_t const*>(iv))) {
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to initialize decryption cipher filter BIO."); // LCOV_EXCL_LINE
    }

    return bio_filter { std::move(bio) };
}

bio_filter bio_filter::decryption(::EVP_CIPHER const* cipher, std::string_view const& password, ::EVP_MD const* digest)
{
    auto const& [key, iv] = _::derive_key_and_iv(cipher, digest, password.data(), password.length(), nullptr, 0, 1000);
    return decryption(cipher, key.data(), key.size(), iv.data(), iv.size());
}

bio bio::from_memory(void const* data, size_t length)
{
    bio_t membufbio { BIO_new_mem_buf(data, length) };
    if (membufbio == nullptr) // LCOV_EXCL_LINE
        CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to allocate OpenSSL static buffer BIO."); // LCOV_EXCL_LINE
    return bio { std::move(membufbio) };
} // LCOV_EXCL_LINE

bio bio::from_fd(int fd)
{
    bio_t fdbio { BIO_new_fd(fd, BIO_NOCLOSE) };
    if (fdbio == nullptr) // LCOV_EXCL_LINE
        CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to allocate OpenSSL fd BIO."); // LCOV_EXCL_LINE
    return bio { std::move(fdbio) };
} // LCOV_EXCL_LINE

void bio::push(bio_filter bio)
{
    std::swap(_bio, bio._bio);
    BIO_push(_bio.get(), bio._bio.release());
}

int bio::write(void const* data, size_t const& length)
{
    return BIO_write(*this, data, length);
}

std::string bio::read_string()
{
    std::stringstream ss;
    while (pending()) {
        std::array<char, 256> buffer { 0 };
        int const nread = BIO_read(*this, buffer.data(), buffer.size());
        if (nread <= 0)
            break;
        ss.write(buffer.data(), nread);
    }
    return ss.str();
}

bool bio::pending() const
{
    return BIO_pending(*this);
}

buffered_bio::buffered_bio()
{
    bio_t membio { BIO_new(BIO_s_mem()) };
    if (membio == nullptr) // LCOV_EXCL_LINE
        CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to allocate OpenSSL dynamic buffer BIO."); // LCOV_EXCL_LINE
    _bio = std::move(membio);
    _ref = _bio.get();
}

std::string buffered_bio::str() const
{
    (void)BIO_flush(*this);
    BUF_MEM* buf = nullptr;
    BIO_get_mem_ptr(_ref, &buf);
    return std::string { buf->data, buf->length };
}

bio& operator<<(bio& bio, char const& ch)
{
    if (BIO_write(bio, &ch, 1) != 1)
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to write character to OpenSSL BIO."); // LCOV_EXCL_LINE
    return bio;
}

bio& operator<<(bio& bio, uint8_t const& byte)
{
    _::bio_write(bio, &byte, 1);
    return bio;
}

bio& operator<<(bio& bio, char const* cstr)
{
    _::bio_write(bio, cstr, strlen(cstr));
    return bio;
}

bio& operator<<(bio& bio, std::string_view const& str)
{
    _::bio_write(bio, str.data(), str.size());
    return bio;
}

bio& operator<<(bio& bio, std::string const& str)
{
    _::bio_write(bio, str.data(), str.size());
    return bio;
}

bio& operator<<(bio& bio, std::vector<uint8_t> const& bytes)
{
    _::bio_write(bio, bytes.data(), bytes.size());
    return bio;
}

} // namespace ossl
