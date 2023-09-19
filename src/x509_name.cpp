//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/x509_name.hpp"
#include "cppossl/error.hpp"

namespace ossl {
namespace x509_name {

    namespace _ {

        static void x509_name_print_text(bio const& bio, ::X509_NAME const* name, int const& flags)
        {
            if (X509_NAME_print_ex(bio, const_cast<X509_NAME*>(name), 0, flags) <= 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to print X509_NAME object to text."); // LCOV_EXCL_LINE
        } // LCOV_EXCL_LINE

        void x509_name_remove_all_by_nid(::X509_NAME* name, int const& nid)
        {
            for (int pos = -1; (pos = X509_NAME_get_index_by_NID(name, nid, pos)) >= 0; pos = -1)
            {
                owned<::X509_NAME_ENTRY> const entry { X509_NAME_delete_entry(name, pos) };
                if (entry == nullptr)
                    CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to remove X509_NAME entry."); // LCOV_EXCL_LINE
            }
        }

        void x509_name_add_by_nid(
            ::X509_NAME* name, int const nid, std::string_view const& value, bool const utf8 = false)
        {
            if (value.empty())
                return;
            x509_name_remove_all_by_nid(name, nid);
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

        void x509_name_add_by_nid(
            ::X509_NAME* name, int const nid, std::vector<std::string> const& values, bool const utf8 = false)
        {
            bool first = true;
            x509_name_remove_all_by_nid(name, nid);
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

        std::string x509_name_entry_to_string(::X509_NAME_ENTRY const* entry)
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

        bool x509_name_get_index(::X509_NAME const* name, int const index, std::string& value)
        {
            X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, index);
            if (entry == nullptr)
                return false;

            value = x509_name_entry_to_string(entry);
            return true;
        }

        bool x509_name_get_nid(::X509_NAME const* name, int const nid, std::string& value)
        {
            int const index = X509_NAME_get_index_by_NID(name, nid, -1);
            if (index < 0)
                return false;

            return x509_name_get_index(name, index, value);
        }

        bool x509_name_get_nid(::X509_NAME const* name, int const nid, std::vector<std::string>& value)
        {
            int count = 0;
            for (int pos = -1; (pos = X509_NAME_get_index_by_NID(name, nid, pos)) >= 0; ++count)
            {
                std::string tmp;
                x509_name_get_index(name, pos, tmp);
                value.push_back(std::move(tmp));
            }
            return count > 0;
        }

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
        _::x509_name_print_text(bio, name.get(), flags);
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

    std::string get_common_name(roref name)
    {
        std::string str;
        (void)_::x509_name_get_nid(name.get(), NID_commonName, str);
        return str;
    } // LCOV_EXCL_LINE

    void set_common_name(rwref name, std::string_view const& value)
    {
        _::x509_name_add_by_nid(name.get(), NID_commonName, value);
    }

    std::string get_locality(roref name)
    {
        std::string str;
        (void)_::x509_name_get_nid(name.get(), NID_localityName, str);
        return str;
    } // LCOV_EXCL_LINE

    void set_locality(rwref name, std::string_view const& value)
    {
        _::x509_name_add_by_nid(name.get(), NID_localityName, value);
    }

    std::string get_state(roref name)
    {
        std::string str;
        (void)_::x509_name_get_nid(name.get(), NID_stateOrProvinceName, str);
        return str;
    } // LCOV_EXCL_LINE

    void set_state(rwref name, std::string_view const& value)
    {
        _::x509_name_add_by_nid(name.get(), NID_stateOrProvinceName, value);
    }

    std::string get_country(roref name)
    {
        std::string str;
        (void)_::x509_name_get_nid(name.get(), NID_countryName, str);
        return str;
    } // LCOV_EXCL_LINE

    void set_country(rwref name, std::string_view const& value)
    {
        if (value.size() > 2)
            CPPOSSL_THROW_ERRNO(EINVAL, "Invalid country name.");
        _::x509_name_add_by_nid(name.get(), NID_countryName, value);
    }

    std::vector<std::string> get_street_address(roref name)
    {
        std::vector<std::string> names;
        (void)_::x509_name_get_nid(name.get(), NID_streetAddress, names);
        return names;
    } // LCOV_EXCL_LINE

    void set_street_address(rwref name, std::vector<std::string> const& value)
    {
        _::x509_name_add_by_nid(name.get(), NID_streetAddress, value);
    }

    std::vector<std::string> get_organization_name(roref name)
    {
        std::vector<std::string> names;
        (void)_::x509_name_get_nid(name.get(), NID_organizationName, names);
        return names;
    } // LCOV_EXCL_LINE

    void set_organization_name(rwref name, std::vector<std::string> const& value)
    {
        _::x509_name_add_by_nid(name.get(), NID_organizationName, value);
    }

    std::vector<std::string> get_organization_unit_name(roref name)
    {
        std::vector<std::string> names;
        (void)_::x509_name_get_nid(name.get(), NID_organizationalUnitName, names);
        return names;
    } // LCOV_EXCL_LINE

    void set_organization_unit_name(rwref name, std::vector<std::string> const& value)
    {
        _::x509_name_add_by_nid(name.get(), NID_organizationalUnitName, value);
    }

    std::vector<std::string> get_domain_components(roref name)
    {
        std::vector<std::string> names;
        (void)_::x509_name_get_nid(name.get(), NID_domainComponent, names);
        return names;
    } // LCOV_EXCL_LINE

    void set_domain_components(rwref name, std::vector<std::string> const& value)
    {
        _::x509_name_add_by_nid(name.get(), NID_domainComponent, value);
    }

    owned<::X509_NAME> build(std::function<void(owned<::X509_NAME>&)> callback)
    {
        auto name = make<::X509_NAME>();
        callback(name);
        return name;
    } // LCOV_EXCL_LINE

} // namespace x509_name
} // namespace ossl
