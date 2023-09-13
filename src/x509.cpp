//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <openssl/pem.h>

#include "cppossl/bio.hpp"
#include "cppossl/error.hpp"
#include "cppossl/raii.hpp"
#include "cppossl/x509.hpp"

namespace ossl {
namespace x509 {

    namespace _ {

        static void x509_print_text(bio const& bio, ::X509 const* x509)
        {
            if (X509_print_ex(bio, const_cast<X509*>(x509), 0, 0) <= 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to print X.509 object to text."); // LCOV_EXCL_LINE
        }

    } // _ namespace

    owned<::X509> retain(roref x509)
    {
        X509_up_ref(const_cast<::X509*>(x509.get()));
        return owned<::X509> { const_cast<::X509*>(x509.get()) };
    }

    bool equal(roref lhs, roref rhs)
    {
        return X509_cmp(lhs.get(), rhs.get()) == 0;
    }

    owned<::X509_NAME> get_issuer(roref x509)
    {
        return owned<::X509_NAME> { X509_NAME_dup(X509_get_issuer_name(x509.get())) };
    }

    owned<::X509_NAME> get_subject(roref x509)
    {
        return owned<::X509_NAME> { X509_NAME_dup(X509_get_subject_name(x509.get())) };
    }

    time_t get_not_before(roref x509)
    {
        ::tm time { 0 };
        if (ASN1_TIME_to_tm(X509_getm_notBefore(x509.get()), &time) != 1)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to parse X.509 not after."); // LCOV_EXCL_LINE

        return timegm(&time);
    }

    time_t get_not_after(roref x509)
    {
        ::tm time { 0 };
        if (ASN1_TIME_to_tm(X509_getm_notAfter(x509.get()), &time) != 1)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to parse X.509 not after."); // LCOV_EXCL_LINE

        return timegm(&time);
    }

    std::string get_serial_number_hex(roref x509)
    {
        owned<::BIGNUM> bn { ASN1_INTEGER_to_BN(X509_get_serialNumber(const_cast<::X509*>(x509.get())), nullptr) };
        if (bn == nullptr)
            CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to allocate OpenSSL BIGNUM object."); // LCOV_EXCL_LINE
        owned<char> const hex { BN_bn2hex(bn.get()) };
        if (hex == nullptr)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to convert OpenSSL BIGNUM object to hex."); // LCOV_EXCL_LINE
        return std::string { hex.get() };
    }

    void print_text(bio const& bio, roref x509)
    {
        _::x509_print_text(bio, x509.get());
    }

    std::string print_text(roref x509)
    {
        buffered_bio bio;
        print_text(bio, x509);
        return bio.str();
    }

    bool check_key(roref x509, raii::roref<::EVP_PKEY> pkey)
    {
        CPPOSSL_ASSERT(x509.get() != nullptr);
        CPPOSSL_ASSERT(pkey.get() != nullptr);
        return X509_check_private_key(const_cast<X509*>(x509.get()), const_cast<EVP_PKEY*>(pkey.get())) == 1;
    }

} // namespace x509
} // namespace ossl
