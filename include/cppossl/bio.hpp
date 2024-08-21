//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include <openssl/types.h>

#include <cppossl/raii.hpp>

namespace ossl {

/**
 * \defgroup bio OpenSSL BIO
 */
/**@{*/

/** @brief BIO filter utility type. */
class bio_filter
{
public:
    static bio_filter base64();

    static bio_filter encryption(
        ::EVP_CIPHER const* cipher, void const* key, size_t const keylen, void const* iv, size_t const ivlen);

    static bio_filter encryption(
        ::EVP_CIPHER const* cipher, std::string_view const& password, ::EVP_MD const* digest = nullptr);

    static bio_filter decryption(
        ::EVP_CIPHER const* cipher, void const* key, size_t const keylen, void const* iv, size_t const ivlen);

    static bio_filter decryption(::EVP_CIPHER const* cipher, std::string_view const& password, ::EVP_MD const* digest);

    static inline bio_filter decryption(::EVP_CIPHER const* cipher, std::string_view const& password)
    {
        return decryption(cipher, password, nullptr);
    }

    bio_filter(bio_filter&&) = default;
    bio_filter& operator=(bio_filter&&) = default;

    bio_filter(bio_filter const&) = delete;
    bio_filter& operator=(bio_filter const&) = delete;

    ~bio_filter() = default;

private:
    bio_filter() noexcept = delete;

    inline explicit bio_filter(owned<::BIO> bio) noexcept
        : _bio(std::move(bio))
    {
    }

    owned<::BIO> _bio;

    friend class bio;
};

/** @brief BIO source/sink utility type. */
class bio
{
public:
    using roref = raii::roref<::BIO>;
    using rwref = raii::rwref<::BIO>;

    /** @brief Allocate an OpenSSL read-only BIO object from a memory buffer. */
    static bio from_memory(void const* data, size_t length);

    /** @brief Allocate an OpenSSL read-only BIO object from a string. */
    inline static bio from_string(std::string_view const& str)
    {
        return from_memory(str.data(), str.size());
    }

    /** @brief Allocate an OpenSSL BIO object from OS file descriptor. */
    static bio from_fd(int fd);

    bio(bio&&) = default;
    bio& operator=(bio&&) = default;

    bio(bio const&) = delete;
    bio& operator=(bio const&) = delete;

    ~bio() = default;

    bool pending() const;

    void push(bio_filter bio);

    std::vector<uint8_t> read();
    std::string read_string();
    int read_into(void* data, size_t const& length);

    int write(void const* data, size_t const& length);

    template <typename T>
    int write(T const& data)
    {
        return write(data.data(), data.size());
    }

    inline operator ::BIO*() const
    {
        return _bio.get();
    }

    inline operator raii::rwref<::BIO>()
    {
        return _bio;
    }

protected:
    bio() noexcept = default;

    inline explicit bio(owned<::BIO> b) noexcept
        : _bio(std::move(b))
    {
    }

    owned<::BIO> _bio;
};

/** @brief Buffered OpenSSL BIO utility type. */
class buffered_bio : public bio
{
public:
    buffered_bio();

    buffered_bio(buffered_bio&&) = default;
    buffered_bio& operator=(buffered_bio&&) = default;

    buffered_bio(buffered_bio const&) = delete;
    buffered_bio& operator=(buffered_bio const&) = delete;

    std::string str() const;

private:
    BIO* _ref { nullptr };
};

bio& operator<<(bio& bio, char const& ch);
bio& operator<<(bio& bio, uint8_t const& byte);

bio& operator<<(bio& bio, char const* cstr);
bio& operator<<(bio& bio, std::string_view const& str);
bio& operator<<(bio& bio, std::string const& str);
bio& operator<<(bio& bio, std::vector<uint8_t> const& bytes);

template <typename T>
bio& operator<<(bio& bio, T const& iterable)
{
    auto const end = iterable.cend();
    for (auto it = iterable.begin(); it != end; ++it)
        bio << *it;
    return bio;
}

/**@}*/

} // namespace ossl
