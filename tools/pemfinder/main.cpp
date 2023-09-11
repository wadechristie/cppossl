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
#include <cppossl/x509_crl.hpp>
#include <cppossl/x509_req.hpp>

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
    bool find_all { true };
    bool find_private_keys { false };
    bool find_x509 { false };
    bool find_x509_crl { false };
    bool find_x509_req { false };
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
              .add_argument(lyra::opt([&args](bool flag) {
                  args.find_all = false;
                  args.find_private_keys = true;
              })
                                .name("--keys")
                                .help("Look for private key objects."))
              .add_argument(lyra::opt([&args](bool flag) {
                  args.find_all = false;
                  args.find_x509_crl = true;
              })
                                .name("--crl")
                                .help("Look for X.509 CRL objects."))
              .add_argument(lyra::opt([&args](bool flag) {
                  args.find_all = false;
                  args.find_x509_req = true;
              })
                                .name("--req")
                                .help("Look for X.X509 request objects."))
              .add_argument(lyra::opt([&args](bool flag) {
                  args.find_all = false;
                  args.find_x509 = true;
              })
                                .name("--x509")
                                .help("Look for X.509 objects."))
              .add_argument(lyra::opt(args.print_text).name("--print-text").help("Print X.509 object information."));

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

    if (args.find_all && !args.print_text)
    {
        while (findpem(std::cin, std::cout))
            continue;
    }
    else
    {
        for (std::stringstream buffer; findpem(std::cin, buffer); buffer = std::stringstream {})
        {
            auto const pem = buffer.str();
            if ((args.find_all || args.find_x509) && starts_with(pem, ossl::pem::x509_begin_line))
            {
                std::cout << pem;

                if (args.print_text)
                {
                    auto const cert = ossl::pem::load<ossl::x509_t>(pem);
                    std::cout << ossl::pem::pem_begin_line_prefix << "CERTIFICATE INFO" << ossl::pem::pem_line_suffix
                              << std::endl;
                    std::cout << ossl::print_text(cert);
                    std::cout << ossl::pem::pem_end_line_prefix << "CERTIFICATE INFO" << ossl::pem::pem_line_suffix
                              << std::endl;
                }
            }
            else if ((args.find_all || args.find_x509_crl) && starts_with(pem, ossl::pem::x509_crl_begin_line))
            {
                std::cout << pem;

                if (args.print_text)
                {
                    auto const crl = ossl::pem::load<ossl::x509_crl_t>(pem);
                    std::cout << ossl::pem::pem_begin_line_prefix << "X509 CRL INFO" << ossl::pem::pem_line_suffix
                              << std::endl;
                    std::cout << ossl::print_text(crl);
                    std::cout << ossl::pem::pem_end_line_prefix << "X509 CRL INFO" << ossl::pem::pem_line_suffix
                              << std::endl;
                }
            }
            else if ((args.find_all || args.find_x509_req) && starts_with(pem, ossl::pem::x509_req_begin_line))
            {
                std::cout << pem;

                if (args.print_text)
                {
                    auto const req = ossl::pem::load<ossl::x509_req_t>(pem);
                    std::cout << ossl::pem::pem_begin_line_prefix << "CERTIFICATE REQUEST INFO"
                              << ossl::pem::pem_line_suffix << std::endl;
                    std::cout << ossl::print_text(req);
                    std::cout << ossl::pem::pem_end_line_prefix << "CERTIFICATE REQUEST INFO"
                              << ossl::pem::pem_line_suffix << std::endl;
                }
            }
            else if ((args.find_all || args.find_private_keys)
                && (starts_with(pem, ossl::pem::pkey_begin_line)
                    || starts_with(pem, ossl::pem::encrypted_pkey_begin_line)))
            {
                std::cout << pem;
            }
        }
    }

    return 0;
}
