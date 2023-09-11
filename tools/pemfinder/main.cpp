//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <iostream>
#include <sstream>
#include <string>

#include <lyra/lyra.hpp>

#include <cppossl/pem.hpp>
#include <cppossl/x509.hpp>

namespace {

bool starts_with(std::string_view const& str, std::string_view const& search)
{
    auto const search_size = search.size();
    if (str.size() < search_size)
        return false;
    return str.compare(0, search_size, search) == 0;
}

bool ends_with(std::string_view const& str, std::string_view const& search)
{
    auto const str_size = str.size();
    auto const search_size = search.size();
    if (str_size < search_size)
        return false;

    return str.compare(str_size - search_size, search_size, search) == 0;
}

bool findpem(std::istream& in, std::ostream& out)
{
    bool found_pem = false;
    for (std::string line; std::getline(std::cin, line);)
    {
        if (!found_pem)
        {
            if (!(starts_with(line, ossl::pem::pem_begin_line_prefix) && ends_with(line, ossl::pem::pem_line_suffix)))
                continue;

            found_pem = true;
            out << line << std::endl;
            continue;
        }

        out << line << std::endl;
        if (starts_with(line, ossl::pem::pem_end_line_prefix))
            break;
    }
    return found_pem;
}

struct cliargs
{
    bool print_text { false };
    bool show_help { false };
};

constexpr char const* help_description = "Extract PEM objects from the input text stream.";

} // namespace

int main(int argc, char const* argv[])
{
    cliargs args;
    auto cli
        = lyra::cli()
              .add_argument(lyra::help(args.show_help).description(help_description))
              .add_argument(lyra::opt(args.print_text).name("--print-text").help("Print certificate information."));

    auto result = cli.parse({ argc, argv });
    if (!result)
    {
        std::cerr << "Error in command line: " << result.message() << std::endl;
        return 1;
    }

    if (args.show_help)
    {
        std::cout << cli << "\n";
        return 0;
    }

    if (args.print_text)
    {
        for (std::stringstream buffer; findpem(std::cin, buffer); buffer = std::stringstream {})
        {
            auto const pem = buffer.str();
            if (starts_with(pem, ossl::pem::x509_begin_line))
            {
                auto const cert = ossl::pem::load<ossl::x509_t>(pem);
                std::cout << pem;
                std::cout << ossl::pem::pem_begin_line_prefix << "CERTIFICATE INFO" << ossl::pem::pem_line_suffix
                          << std::endl;
                std::cout << ossl::print_text(cert);
                std::cout << ossl::pem::pem_end_line_prefix << "CERTIFICATE INFO" << ossl::pem::pem_line_suffix
                          << std::endl;
            }
        }
    }
    else
    {
        while (findpem(std::cin, std::cout))
            continue;
    }

    return 0;
}
