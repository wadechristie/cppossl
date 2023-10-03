//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <sstream>

#include "cppossl/error.hpp"
#include "cppossl/x509_name.hpp"

namespace ossl {
namespace x509_name {

    namespace _ {

        std::string_view trim(std::string_view const& str)
        {
            std::string_view result;
            char const* left = str.begin();
            for (;; ++left)
            {
                if (left == str.end())
                    return std::string_view {};
                if (!isspace(*left))
                    break;
            }
            char const* right = str.end() - 1;
            for (; right > left && isspace(*right); --right)
                continue;
            CPPOSSL_ASSERT(std::distance(left, right) >= 0);
            return { left, static_cast<size_t>(std::distance(left, right)) + 1 };
        }

        void print_text(bio const& bio, ::X509_NAME const* name, int const& flags)
        {
            if (X509_NAME_print_ex(bio, const_cast<X509_NAME*>(name), 0, flags) <= 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to print X509_NAME object to text."); // LCOV_EXCL_LINE
        } // LCOV_EXCL_LINE

        void remove_all_by_nid(::X509_NAME* name, int const& nid)
        {
            for (int pos = -1; (pos = X509_NAME_get_index_by_NID(name, nid, pos)) >= 0; pos = -1)
            {
                owned<::X509_NAME_ENTRY> const entry { X509_NAME_delete_entry(name, pos) };
                if (entry == nullptr)
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to remove X509_NAME entry."); // LCOV_EXCL_LINE
            }
        }

        void add_by_nid(::X509_NAME* name, int const nid, std::string_view const& value, bool const utf8 = false)
        {
            if (value.empty())
                return;
            remove_all_by_nid(name, nid);
            int const rc = X509_NAME_add_entry_by_NID(name,
                nid,
                utf8 ? MBSTRING_UTF8 : MBSTRING_ASC,
                const_cast<uint8_t*>(reinterpret_cast<uint8_t const*>(value.data())),
                value.size(),
                /*loc=*/-1,
                /*set=*/0);
            if (rc == 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to add entry to X509_NAME object."); // LCOV_EXCL_LINE
        }

        void append_by_nid(::X509_NAME* name, int const nid, std::string_view const& value, bool const utf8 = false)
        {
            if (value.empty())
                return;
            int const rc = X509_NAME_add_entry_by_NID(name,
                nid,
                utf8 ? MBSTRING_UTF8 : MBSTRING_ASC,
                const_cast<uint8_t*>(reinterpret_cast<uint8_t const*>(value.data())),
                value.size(),
                /*loc=*/-1,
                /*set=*/1);
            if (rc == 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to add entry to X509_NAME object."); // LCOV_EXCL_LINE
        }

        void add_by_nid(
            ::X509_NAME* name, int const nid, std::vector<std::string> const& values, bool const utf8 = false)
        {
            bool first = true;
            remove_all_by_nid(name, nid);
            for (auto const& value : values)
            {
                if (value.empty())
                    continue; // LCOV_EXCL_LINE
                int const rc = X509_NAME_add_entry_by_NID(name,
                    nid,
                    utf8 ? MBSTRING_UTF8 : MBSTRING_ASC,
                    const_cast<uint8_t*>(reinterpret_cast<uint8_t const*>(value.c_str())),
                    value.size(),
                    /*loc=*/-1,
                    /*set=*/(first ? 0 : 1));
                if (rc == 0)
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                        "Failed to add a new entry to X509_NAME object.");
                first = false;
            }
        }

        std::string entry_to_string(::X509_NAME_ENTRY const* entry)
        {
            std::string name;

            owned<uint8_t> buf;
            ASN1_STRING const* data = X509_NAME_ENTRY_get_data(entry);
            int const buflen = ASN1_STRING_to_UTF8(buf.capture(), data);
            if (buflen <= 0)
                return name; // LCOV_EXCL_LINE

            name = std::string(reinterpret_cast<const char*>(buf.get()), buflen);
            return name;
        }

        bool get_index(::X509_NAME const* name, int const index, std::string& value)
        {
            X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, index);
            if (entry == nullptr)
                return false;

            value = entry_to_string(entry);
            return true;
        }

        bool get_nid(::X509_NAME const* name, int const nid, std::string& value)
        {
            int const index = X509_NAME_get_index_by_NID(name, nid, -1);
            if (index < 0)
                return false;

            return get_index(name, index, value);
        }

        bool get_nid(::X509_NAME const* name, int const nid, std::vector<std::string>& value)
        {
            int count = 0;
            for (int pos = -1; (pos = X509_NAME_get_index_by_NID(name, nid, pos)) >= 0; ++count)
            {
                std::string tmp;
                get_index(name, pos, tmp);
                value.push_back(std::move(tmp));
            }
            return count > 0;
        }

        /**
         * @brief X.509 name string parser.
         **/
        class parser
        {
            enum class tokentag : uint8_t
            {
                END,
                LITERAL,
                COMMA,
                EQUAL
            };

            struct token
            {
                token() = default;

                token(tokentag tag, std::string value)
                    : _tag(tag)
                    , _value(std::move(value))
                {
                }

                token(token&&) = default;
                token& operator=(token&&) = default;

                token(token const&) = default;
                token& operator=(token const&) = default;

                ~token() = default;

                tokentag tag() const noexcept
                {
                    return _tag;
                }

                std::string const& value() const noexcept
                {
                    return _value;
                }

            private:
                tokentag _tag { tokentag::END };
                std::string _value;
            };

            std::istream& _input;
            owned<::X509_NAME> _name;

            bool is_whitespace(char const ch)
            {
                return std::isspace(ch);
            }

            bool is_sentinel(char const ch)
            {
                switch (ch)
                {
                case ',':
                case '=':
                    return true;

                default:
                    return false;
                }
            }

            char advance()
            {
                auto const v = _input.get();
                if (v == std::istream::traits_type::eof())
                    return 0;
                return v;
            }

            char peek()
            {
                auto const v = _input.peek();
                if (v == std::istream::traits_type::eof())
                    return 0;
                return v;
            }

            token literal()
            {
                bool quoted = false;
                std::string value;
                while (true)
                {
                    char const ch = peek();

                    if (quoted)
                    {
                        if (ch == 0)
                            CPPOSSL_THROW_ERRNO(
                                EINVAL, "Invalid X.509 name format, contained unterminated quouted string");

                        if (ch == '"')
                        {
                            (void)advance();
                            quoted = false;
                            continue;
                        }
                    }
                    else
                    {
                        if (ch == '"')
                        {
                            (void)advance();
                            quoted = true;
                            continue;
                        }

                        if (ch == 0 || is_sentinel(ch))
                            break;
                    }

                    (void)advance();
                    value.push_back(ch);
                }

                return token { tokentag::LITERAL, std::string { trim(value) } };
            }

            token next()
            {
                token tok;
                char ch = peek();
                while (is_whitespace(ch))
                {
                    (void)advance();
                    ch = peek();
                }
                switch (ch)
                {
                case 0:
                    break;

                case ',':
                    (void)advance();
                    tok = token(tokentag::COMMA, {});
                    break;

                case '=':
                    (void)advance();
                    tok = token(tokentag::EQUAL, {});
                    break;

                default:
                    tok = literal();
                    break;
                }

                return tok;
            }

            token match(tokentag const tag)
            {
                token tok = next();
                if (tok.tag() != tag)
                    CPPOSSL_THROW_ERRNO(EINVAL, "Invalid X.509 name format");
                return tok;
            }

            void parse_component()
            {
                token const key = match(tokentag::LITERAL);
                (void)match(tokentag::EQUAL);
                token const value = match(tokentag::LITERAL);

                int const nid = OBJ_txt2nid(key.value().c_str());
                if (nid == NID_undef)
                    CPPOSSL_THROW_ERRNO(EINVAL, "Invalid X.509 name component type");

                int const index = X509_NAME_get_index_by_NID(_name.get(), nid, -1);
                if (index < 0)
                    add_by_nid(_name.get(), nid, value.value(), /*uft8=*/false);
                else
                    append_by_nid(_name.get(), nid, value.value(), /*uft8=*/false);
            }

        public:
            explicit parser(std::istream& input)
                : _input(input)
            {
            }

            owned<::X509_NAME> parse()
            {
                _name = make<::X509_NAME>();

                while (true)
                {
                    parse_component();
                    token const tok = next();
                    if (tok.tag() == tokentag::END)
                        break;
                    if (tok.tag() != tokentag::COMMA)
                        CPPOSSL_THROW_ERRNO(EINVAL, "Invalid X.509 name format");
                }

                return std::move(_name);
            }
        };

    } // _ namespace

    int cmp(roref left, roref right)
    {
        auto const result = X509_NAME_cmp(left.get(), right.get());
        if (result == -2)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                "Encountered an error while attempting to compare two OpenSSL X509_NAME objects.");
        return result;
    }

    void print_text(bio const& bio, roref name)
    {
        print_text(bio, name.get(), XN_FLAG_ONELINE);
    }

    void print_text(bio const& bio, roref name, int flags)
    {
        _::print_text(bio, name.get(), flags);
    }

    std::string print_text(roref name)
    {
        return print_text(name, XN_FLAG_ONELINE);
    }

    std::string print_text(roref name, int flags)
    {
        buffered_bio bio;
        print_text(bio, name, flags);
        return bio.str();
    }

    owned<::X509_NAME> parse(std::string const& str)
    {
        std::stringstream ss(str, std::ios::in);
        _::parser p(ss);
        return p.parse();
    }

    std::string get_common_name(roref name)
    {
        std::string str;
        (void)_::get_nid(name.get(), NID_commonName, str);
        return str;
    } // LCOV_EXCL_LINE

    void set_common_name(rwref name, std::string_view const& value)
    {
        _::add_by_nid(name.get(), NID_commonName, value);
    }

    std::string get_locality(roref name)
    {
        std::string str;
        (void)_::get_nid(name.get(), NID_localityName, str);
        return str;
    } // LCOV_EXCL_LINE

    void set_locality(rwref name, std::string_view const& value)
    {
        _::add_by_nid(name.get(), NID_localityName, value);
    }

    std::string get_state(roref name)
    {
        std::string str;
        (void)_::get_nid(name.get(), NID_stateOrProvinceName, str);
        return str;
    } // LCOV_EXCL_LINE

    void set_state(rwref name, std::string_view const& value)
    {
        _::add_by_nid(name.get(), NID_stateOrProvinceName, value);
    }

    std::string get_country(roref name)
    {
        std::string str;
        (void)_::get_nid(name.get(), NID_countryName, str);
        return str;
    } // LCOV_EXCL_LINE

    void set_country(rwref name, std::string_view const& value)
    {
        if (value.size() > 2)
            CPPOSSL_THROW_ERRNO(EINVAL, "Invalid country name.");
        _::add_by_nid(name.get(), NID_countryName, value);
    }

    std::vector<std::string> get_street_address(roref name)
    {
        std::vector<std::string> names;
        (void)_::get_nid(name.get(), NID_streetAddress, names);
        return names;
    } // LCOV_EXCL_LINE

    void set_street_address(rwref name, std::vector<std::string> const& value)
    {
        _::add_by_nid(name.get(), NID_streetAddress, value);
    }

    std::vector<std::string> get_organization_name(roref name)
    {
        std::vector<std::string> names;
        (void)_::get_nid(name.get(), NID_organizationName, names);
        return names;
    } // LCOV_EXCL_LINE

    void set_organization_name(rwref name, std::vector<std::string> const& value)
    {
        _::add_by_nid(name.get(), NID_organizationName, value);
    }

    std::vector<std::string> get_organization_unit_name(roref name)
    {
        std::vector<std::string> names;
        (void)_::get_nid(name.get(), NID_organizationalUnitName, names);
        return names;
    } // LCOV_EXCL_LINE

    void set_organization_unit_name(rwref name, std::vector<std::string> const& value)
    {
        _::add_by_nid(name.get(), NID_organizationalUnitName, value);
    }

    std::vector<std::string> get_domain_components(roref name)
    {
        std::vector<std::string> names;
        (void)_::get_nid(name.get(), NID_domainComponent, names);
        return names;
    } // LCOV_EXCL_LINE

    void set_domain_components(rwref name, std::vector<std::string> const& value)
    {
        _::add_by_nid(name.get(), NID_domainComponent, value);
    }

    owned<::X509_NAME> build(std::function<void(owned<::X509_NAME>&)> callback)
    {
        auto name = make<::X509_NAME>();
        callback(name);
        return name;
    } // LCOV_EXCL_LINE

} // namespace x509_name
} // namespace ossl
