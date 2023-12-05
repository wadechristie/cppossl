//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <openssl/stack.h>

#include <cppossl/raii.hpp>

namespace ossl {
namespace stack {

    /**
     * \defgroup stack OpenSSL Stack Helpers
     */
    /**@{*/

    template <typename StackT>
    raii::owned<StackT> make()
    {
        static_assert(raii::traits<typename StackT::type>::is_stack, "Requires OpenSSL RAII stack type!");
        return raii::owned<StackT>::make();
    }

    template <typename StackT>
    size_t size(StackT const& sk)
    {
        static_assert(raii::traits<typename StackT::type>::is_stack, "Requires OpenSSL RAII stack type!");
        return OPENSSL_sk_num(reinterpret_cast<OPENSSL_STACK*>(sk.get()));
    }

    template <typename StackT>
    bool empty(StackT const& sk)
    {
        return size(sk) == 0;
    }

    template <typename StackT>
    void push(StackT const& sk, raii::owned<typename raii::traits<typename StackT::type>::elem_type> elem)
    {
        static_assert(raii::traits<typename StackT::type>::is_stack, "Requires OpenSSL RAII stack type!");

        if (!OPENSSL_sk_push(reinterpret_cast<OPENSSL_STACK*>(sk.get()), elem.get()))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to push element onto stack."); // LCOV_EXCL_LINE
        elem.release();
    }

    template <typename StackT>
    void push(StackT const& sk, raii::roref<typename raii::traits<typename StackT::type>::elem_type> elem)
    {
        static_assert(raii::traits<typename StackT::type>::is_stack, "Requires OpenSSL RAII stack type!");

        if (!OPENSSL_sk_push(reinterpret_cast<OPENSSL_STACK*>(sk.get()), elem.get()))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to push element onto stack."); // LCOV_EXCL_LINE
    }

    template <typename StackT>
    raii::owned<typename raii::traits<typename StackT::type>::elem_type> pop(StackT const& sk)
    {
        static_assert(raii::traits<typename StackT::type>::is_stack, "Requires OpenSSL RAII stack type!");

        return raii::owned<typename raii::traits<typename StackT::type>::elem_type> {
            reinterpret_cast<typename raii::traits<typename StackT::type>::elem_type*>(
                OPENSSL_sk_pop(reinterpret_cast<OPENSSL_STACK*>(sk.get())))
        };
    }

    /**@}*/

} // namespace stack
} // namespace ossl
