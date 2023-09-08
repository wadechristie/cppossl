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

namespace _ {

    static void x509_print_text(bio const& bio, ::X509 const* x509)
    {
        if (X509_print_ex(bio, const_cast<X509*>(x509), 0, 0) <= 0)
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to print X.509 object to text."); // LCOV_EXCL_LINE
    }

} // _ namespace

x509_t new_ref(x509_t const& x509)
{
    X509_up_ref(x509.get());
    return x509_t { x509.get() };
}

bool equal(x509_t const& lhs, x509_t const& rhs)
{
    return X509_cmp(lhs.get(), rhs.get()) == 0;
}

x509_name_t get_issuer(::X509 const* x509)
{
    return x509_name_t { X509_NAME_dup(X509_get_issuer_name(x509)) };
}

x509_name_t get_subject(::X509 const* x509)
{
    return x509_name_t { X509_NAME_dup(X509_get_subject_name(x509)) };
}

time_t get_not_before(::X509 const* x509)
{
    ::tm time { 0 };
    if (ASN1_TIME_to_tm(X509_getm_notBefore(x509), &time) != 1)
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to parse X.509 not after."); // LCOV_EXCL_LINE

    return timegm(&time);
}

time_t get_not_after(::X509 const* x509)
{
    ::tm time { 0 };
    if (ASN1_TIME_to_tm(X509_getm_notAfter(x509), &time) != 1)
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to parse X.509 not after."); // LCOV_EXCL_LINE

    return timegm(&time);
}

std::string get_serial_number_hex(::X509 const* x509)
{
    bignum_t bn { ASN1_INTEGER_to_BN(X509_get_serialNumber(const_cast<::X509*>(x509)), nullptr) };
    if (bn == nullptr)
        CPPOSSL_THROW_ERRNO(ENOMEM, "Failed to allocate OpenSSL BIGNUM object."); // LCOV_EXCL_LINE
    ossl_cstring_t const hex { BN_bn2hex(bn.get()) };
    if (hex == nullptr)
        CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to convert OpenSSL BIGNUM object to hex."); // LCOV_EXCL_LINE
    return std::string { hex.get() };
}

void print_text(bio const& bio, ::X509 const* x509)
{
    _::x509_print_text(bio, x509);
}

std::string print_text(::X509 const* x509)
{
    buffered_bio bio;
    print_text(bio, x509);
    return bio.str();
}

bool check_key(::X509 const* x509, ::EVP_PKEY const* pkey)
{
    CPPOSSL_ASSERT(x509 != nullptr);
    CPPOSSL_ASSERT(pkey != nullptr);
    return X509_check_private_key(const_cast<X509*>(x509), const_cast<EVP_PKEY*>(pkey)) == 1;
}

} // namespace ossl
