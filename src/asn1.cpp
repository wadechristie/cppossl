//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "cppossl/asn1_bit_string.hpp"
#include "cppossl/asn1_integer.hpp"
#include "cppossl/asn1_time.hpp"
#include "cppossl/error.hpp"

namespace ossl {
namespace asn1 {
    namespace bit_string {

        void set_bit(rwref bitstr, uint8_t index, bool value)
        {
            if (ASN1_BIT_STRING_set_bit(bitstr.get(), static_cast<int>(index), value ? 1 : 0) != 1)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                    "Failed to set bit in ASN1_BIT_STRING.");
        }

        bool is_set(roref bitstr, uint8_t index)
        {
            return ASN1_BIT_STRING_get_bit(bitstr.get(), static_cast<int>(index));
        }

    } // namespace bit_string

    namespace integer {

        owned<::ASN1_INTEGER> make(uint64_t value)
        {
            auto i = ossl::make<asn1::INTEGER>();
            if (ASN1_INTEGER_set_uint64(i.get(), value) == 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                    "Failed to set ASN1_INTEGER object with unsigned integer value."); // LCOV_EXCL_LINE
            return i;
        } // LCOV_EXCL_LINE

        owned<::ASN1_INTEGER> make(ossl::raii::roref<::BIGNUM> value)
        {
            auto i = ossl::make<asn1::INTEGER>();
            if (BN_to_ASN1_INTEGER(value.get(), i.get()) == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                    "Failed to convert BIGNUM object to ASN1_INTEGER object."); // LCOV_EXCL_LINE
            return i;
        } // LCOV_EXCL_LINE

    } // namespace integer

    namespace string {

        void set(raii::rwref<::ASN1_STRING> str, std::string_view value)
        {
            if (ASN1_STRING_type(str.get()) != asn1::IA5STRING && ASN1_STRING_type(str.get()) != asn1::UTF8STRING)
                throw std::runtime_error("Operation not supported on ASN1_STRING type.");

            if (value.size() > std::numeric_limits<int>::max())
                throw std::runtime_error("Input string too large for ASN1_STRING construction."); // LCOV_EXCL_LINE

            if (!ASN1_STRING_set(str.get(), value.data(), static_cast<int>(value.size())))
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to set ASN1_STRING value."); // LCOV_EXCL_LINE
        }

    } // namespace string

    namespace time {

        int cmp(roref left, roref right)
        {
            auto const result = ASN1_TIME_compare(left.get(), right.get());
            if (result == -2)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                    "Encountered an error while attempting to compare two OpenSSL ASN1_TIME objects.");
            return result;
        }

        owned<::ASN1_TIME> dup(roref time)
        {
            owned<::ASN1_TIME> t { ASN1_TIME_dup(time.get()) };
            if (t == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to duplicate ASN1_TIME."); // LCOV_EXCL_LINE
            return t;
        } // LCOV_EXCL_LINE

        owned<::ASN1_TIME> now()
        {
            return offset(std::chrono::seconds::zero());
        }

        owned<::ASN1_TIME> offset(std::chrono::seconds const& from_now)
        {
            owned<::ASN1_TIME> t { X509_time_adj_ex(nullptr, 0, from_now.count(), nullptr) };
            if (t == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to create ASN1_TIME from offset."); // LCOV_EXCL_LINE
            return t;
        } // LCOV_EXCL_LINE

        owned<::ASN1_TIME> from_unix(time_t const& unixts)
        {
            time_t tmp = unixts;
            owned<::ASN1_TIME> t { X509_time_adj_ex(nullptr, 0, 0, &tmp) };
            if (t == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to update ASN1_TIME from unix timestamp."); // LCOV_EXCL_LINE
            return t;
        } // LCOV_EXCL_LINE

        time_t to_unix(roref in)
        {
            ::tm t {};
            if (ASN1_TIME_to_tm(in.get(), &t) != 1)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to parse ASN1_TIME to tm struct."); // LCOV_EXCL_LINE
            return timegm(&t);
        } // LCOV_EXCL_LINE

        void set_offset(rwref t, std::chrono::seconds const& from_now)
        {
            if (X509_time_adj_ex(t.get(), 0, from_now.count(), nullptr) == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to update ASN1_TIME offset."); // LCOV_EXCL_LINE
        } // LCOV_EXCL_LINE

        void set_unix(rwref t, time_t const& unixts)
        {
            time_t tmp = unixts;
            if (X509_time_adj_ex(t.get(), 0, 0, &tmp) == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to update ASN1_TIME from unix timestamp."); // LCOV_EXCL_LINE
        } // LCOV_EXCL_LINE

    } // namespace time

} // namespace asn1
} // namespace ossl
