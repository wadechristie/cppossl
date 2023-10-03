//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>

#include <cppossl/x509_name.hpp>

TEST_CASE("X.509 Name", "[x509][x509_name]")
{
    auto name = ossl::make<::X509_NAME>();
    REQUIRE(name);

    SECTION("set_common_name()")
    {
        REQUIRE_NOTHROW(ossl::x509_name::set_common_name(name, "test_common_name"));
        REQUIRE(ossl::x509_name::get_common_name(name) == "test_common_name");
        REQUIRE(ossl::x509_name::print_text(name) == "CN = test_common_name");

        REQUIRE_NOTHROW(ossl::x509_name::set_common_name(name, "new_common_name"));
        REQUIRE(ossl::x509_name::get_common_name(name) == "new_common_name");
        REQUIRE(ossl::x509_name::print_text(name) == "CN = new_common_name");
    }

    SECTION("set_locality()")
    {
        REQUIRE_NOTHROW(ossl::x509_name::set_locality(name, "test_locality"));
        REQUIRE(ossl::x509_name::get_locality(name) == "test_locality");
        REQUIRE(ossl::x509_name::print_text(name) == "L = test_locality");

        REQUIRE_NOTHROW(ossl::x509_name::set_locality(name, "new_locality"));
        REQUIRE(ossl::x509_name::get_locality(name) == "new_locality");
        REQUIRE(ossl::x509_name::print_text(name) == "L = new_locality");
    }

    SECTION("set_state()")
    {
        REQUIRE_NOTHROW(ossl::x509_name::set_state(name, "test_state"));
        REQUIRE(ossl::x509_name::get_state(name) == "test_state");
        REQUIRE(ossl::x509_name::print_text(name) == "ST = test_state");

        REQUIRE_NOTHROW(ossl::x509_name::set_state(name, "new_state"));
        REQUIRE(ossl::x509_name::get_state(name) == "new_state");
        REQUIRE(ossl::x509_name::print_text(name) == "ST = new_state");
    }

    SECTION("set_country()")
    {
        REQUIRE_THROWS_AS(ossl::x509_name::set_country(name, "United States"), std::system_error);

        REQUIRE_NOTHROW(ossl::x509_name::set_country(name, "US"));
        REQUIRE(ossl::x509_name::get_country(name) == "US");
        REQUIRE(ossl::x509_name::print_text(name) == "C = US");

        REQUIRE_NOTHROW(ossl::x509_name::set_country(name, "UK"));
        REQUIRE(ossl::x509_name::get_country(name) == "UK");
        REQUIRE(ossl::x509_name::print_text(name) == "C = UK");
    }

    SECTION("set_street_address()")
    {
        REQUIRE_NOTHROW(ossl::x509_name::set_street_address(name, { "First Address", "Second Address" }));
        REQUIRE(ossl::x509_name::print_text(name) == "street = First Address, street = Second Address");

        REQUIRE_NOTHROW(ossl::x509_name::set_street_address(
            name, { "New First Address", "New Second Address", "New Third Address" }));
        REQUIRE(ossl::x509_name::print_text(name)
            == "street = New First Address, street = New Second Address, street = New Third Address");
    }

    SECTION("set_domain_components()")
    {
        REQUIRE_NOTHROW(ossl::x509_name::set_domain_components(name, { "example", "com" }));
        REQUIRE(ossl::x509_name::print_text(name) == "DC = example, DC = com");

        REQUIRE_NOTHROW(ossl::x509_name::set_domain_components(name, { "sub", "example", "com" }));
        REQUIRE(ossl::x509_name::print_text(name) == "DC = sub, DC = example, DC = com");
    }

    SECTION("Complex Name")
    {
        std::string const common_name = "Martin Stadium";
        std::string const locality = "Pullman";
        std::string const state = "Washington";
        std::string const country = "US";
        std::vector<std::string> const street_address {
            "1775 NE Stadium Way",
        };
        std::vector<std::string> const org_name {
            "Washington State University",
        };
        std::vector<std::string> const org_unit_name {
            "Washington State University Athletics",
        };
        std::vector<std::string> const domain_components {
            "wsustadium",
            "com",
        };

        REQUIRE_NOTHROW(ossl::x509_name::set_common_name(name, common_name));
        REQUIRE_NOTHROW(ossl::x509_name::set_locality(name, locality));
        REQUIRE_NOTHROW(ossl::x509_name::set_state(name, state));
        REQUIRE_NOTHROW(ossl::x509_name::set_country(name, country));
        REQUIRE_NOTHROW(ossl::x509_name::set_street_address(name, street_address));
        REQUIRE_NOTHROW(ossl::x509_name::set_organization_name(name, org_name));
        REQUIRE_NOTHROW(ossl::x509_name::set_organization_unit_name(name, org_unit_name));
        REQUIRE_NOTHROW(ossl::x509_name::set_domain_components(name, domain_components));

        REQUIRE(ossl::x509_name::get_common_name(name) == common_name);
        REQUIRE(ossl::x509_name::get_locality(name) == locality);
        REQUIRE(ossl::x509_name::get_state(name) == state);
        REQUIRE(ossl::x509_name::get_country(name) == country);
        REQUIRE_THAT(ossl::x509_name::get_street_address(name), Catch::Matchers::UnorderedEquals(street_address));
        REQUIRE_THAT(ossl::x509_name::get_organization_name(name), Catch::Matchers::UnorderedEquals(org_name));
        REQUIRE_THAT(
            ossl::x509_name::get_organization_unit_name(name), Catch::Matchers::UnorderedEquals(org_unit_name));
        REQUIRE_THAT(ossl::x509_name::get_domain_components(name), Catch::Matchers::UnorderedEquals(domain_components));
        REQUIRE(ossl::x509_name::print_text(name)
            == "CN = Martin Stadium, L = Pullman, ST = Washington, C = US, street = 1775 NE"
               " Stadium Way, O = Washington State University, OU = Washington State"
               " University Athletics, DC = wsustadium, DC = com");
    }
}

TEST_CASE("X.509 Name - Parse", "[x509][x509_name]")
{
    SECTION("Valid Name")
    {
        std::string const common_name = "Martin Stadium";
        std::string const locality = "Pullman";
        std::string const state = "Washington";
        std::string const country = "US";
        std::vector<std::string> const street_address {
            "1775 NE Stadium Way",
        };
        std::vector<std::string> const org_name {
            "Washington State University",
        };
        std::vector<std::string> const org_unit_name {
            "Washington State University Athletics",
        };
        std::vector<std::string> const domain_components {
            "wsustadium",
            "com",
        };

        auto const namestr = "CN = Martin Stadium, L = Pullman, ST = Washington, C = US, street = 1775 NE"
                             " Stadium Way, O = \"Washington State University\", OU = Washington State"
                             " University Athletics, DC = wsustadium, DC = com";

        ossl::owned<::X509_NAME> name;
        REQUIRE_NOTHROW(name = ossl::x509_name::parse(namestr));
        REQUIRE(name);

        REQUIRE(ossl::x509_name::get_common_name(name) == common_name);
        REQUIRE(ossl::x509_name::get_locality(name) == locality);
        REQUIRE(ossl::x509_name::get_state(name) == state);
        REQUIRE(ossl::x509_name::get_country(name) == country);
        REQUIRE_THAT(ossl::x509_name::get_street_address(name), Catch::Matchers::UnorderedEquals(street_address));
        REQUIRE_THAT(ossl::x509_name::get_organization_name(name), Catch::Matchers::UnorderedEquals(org_name));
        REQUIRE_THAT(
            ossl::x509_name::get_organization_unit_name(name), Catch::Matchers::UnorderedEquals(org_unit_name));
        REQUIRE_THAT(ossl::x509_name::get_domain_components(name), Catch::Matchers::UnorderedEquals(domain_components));
        REQUIRE(ossl::x509_name::print_text(name)
            == "CN = Martin Stadium, L = Pullman, ST = Washington, C = US, street = 1775 NE"
               " Stadium Way, O = Washington State University, OU = Washington State"
               " University Athletics, DC = wsustadium, DC = com");
    }

    SECTION("Invalid Component")
    {
        REQUIRE_THROWS_AS(ossl::x509_name::parse("CN = Martin Stadium, Pullman, WA"), std::system_error);
    }

    SECTION("Invalid Component Type")
    {
        REQUIRE_THROWS_AS(ossl::x509_name::parse("CN = Martin Stadium, oops = Pullman"), std::system_error);

        auto const invalidquoted = "CN = Martin Stadium, L = Pullman, ST = Washington, C = US, street = 1775 NE"
                                   " Stadium Way, O = \"Washington State University, OU = Washington State"
                                   " University Athletics, DC = wsustadium, DC = com";
        REQUIRE_THROWS_AS(ossl::x509_name::parse(invalidquoted), std::system_error);
    }
}
