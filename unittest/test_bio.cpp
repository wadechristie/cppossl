//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <sstream>

#include <catch2/catch_test_macros.hpp>

#include <cppossl/bio.hpp>

#include "common.hpp"

using namespace ossl;

TEST_CASE("buffered_bio", "[bio]")
{
    std::string const password = "abcdefghijklmnopqrstuvwxyz";
    std::string const cleartext = "Hello world!";
    std::string ciphertext;

    // SECTION("Encrypt")
    {
        buffered_bio bio;
        bio.push(bio_filter::base64());
        bio.push(bio_filter::encryption(EVP_aes_256_cbc(), password));

        bio.write(cleartext);
        ciphertext = bio.str();
        REQUIRE(ciphertext != cleartext);
    }

    // SECTION("Decrypt")
    {
        INFO("ciphertext: " << ciphertext);
        REQUIRE_FALSE(ciphertext.empty());

        bio bio = bio::from_string(ciphertext);
        bio.push(bio_filter::base64());
        bio.push(bio_filter::decryption(EVP_aes_256_cbc(), password));

        auto const decoded_cleartext = bio.read_string();
        REQUIRE(decoded_cleartext == cleartext);
    }
}

TEST_CASE("buffered_bio operator<<", "[bio]")
{
    buffered_bio bio;

    SECTION("CString")
    {
        char const* hello_world = "Hello world";
        bio << hello_world;
        REQUIRE(bio.str() == hello_world);
    }

    SECTION("std::string")
    {
        std::string const hello_world = "Hello world";
        bio.write(hello_world);
        REQUIRE(bio.str() == hello_world);
    }

    SECTION("std::string_view")
    {
        std::string_view const hello_world = "Hello world";
        bio << hello_world;
        REQUIRE(bio.str() == hello_world);
    }

    SECTION("std::vector<uint8_t>")
    {
        std::string const hello_world = "Hello world";
        std::vector<uint8_t> vec;
        for (auto const& ch : hello_world)
            vec.push_back(ch);
        bio << vec;
        REQUIRE(bio.str() == hello_world);
    }

    SECTION("Composable Iterable")
    {
        std::vector<std::string> const strings = { { "one", "two", "three" } };
        bio << strings;
        REQUIRE(bio.str() == "onetwothree");
    }
}
