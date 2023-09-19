//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>

#include <cppossl/error.hpp>
#include <cppossl/x509_store.hpp>

#include "common.hpp"

using namespace ossl;

struct x509_store_test
{
    static owned<::X509_NAME> name(std::string_view const& common_name)
    {
        return x509_name::build([&common_name](owned<::X509_NAME>& name) {
            x509_name::set_organization_name(name,
                {
                    "X.509 CRL Builder",
                });
            x509_name::set_common_name(name, common_name);
        });
    }

    static owned<::EVP_PKEY> const signing_key;
    static owned<::X509> const signing_cert;
};

TEST_CASE_METHOD(x509_store_test, "X.509 Store", "[x509_store]")
{
    auto store = make<::X509_STORE>();

    REQUIRE_NOTHROW(x509_store::set_flags(store, X509_V_FLAG_X509_STRICT));
    REQUIRE_NOTHROW(x509_store::set_depth(store, 0));
}

TEST_CASE_METHOD(x509_store_test, "X.509 Store - Retain", "[x509_store]")
{
    owned<::X509_STORE> store;
    REQUIRE_FALSE(store);

    {
        auto innerstore = make<::X509_STORE>();
        REQUIRE(innerstore);
        REQUIRE_NOTHROW(store = x509_store::retain(innerstore));
    }

    REQUIRE(store);
}
