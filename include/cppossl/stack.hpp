//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <algorithm>

#include <openssl/stack.h>
#include <openssl/x509.h>

#include <cppossl/error.hpp>
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
    size_t size(StackT& sk)
    {
        static_assert(raii::traits<typename StackT::type>::is_stack, "Requires OpenSSL RAII stack type!");
        return OPENSSL_sk_num(reinterpret_cast<OPENSSL_STACK*>(sk.get()));
    }

    template <typename StackT>
    bool empty(StackT& sk)
    {
        return size(sk) == 0;
    }

    template <typename StackT, typename IndexT>
    typename raii::traits<typename StackT::type>::elem_type* get(StackT& sk, IndexT index)
    {
        static_assert(raii::traits<typename StackT::type>::is_stack, "Requires OpenSSL RAII stack type!");

        return reinterpret_cast<typename raii::traits<typename StackT::type>::elem_type*>(
            OPENSSL_sk_value(reinterpret_cast<OPENSSL_STACK*>(sk.get()), static_cast<int>(index)));
    }

    template <typename StackT>
    void push(StackT& sk, raii::owned<typename raii::traits<typename StackT::type>::elem_type> elem)
    {
        static_assert(raii::traits<typename StackT::type>::is_stack, "Requires OpenSSL RAII stack type!");

        if (!OPENSSL_sk_push(reinterpret_cast<OPENSSL_STACK*>(sk.get()), elem.get()))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to push element onto stack."); // LCOV_EXCL_LINE
        elem.release();
    }

    template <typename StackT>
    void push(StackT& sk, raii::roref<typename raii::traits<typename StackT::type>::elem_type> elem)
    {
        static_assert(raii::traits<typename StackT::type>::is_stack, "Requires OpenSSL RAII stack type!");

        if (!OPENSSL_sk_push(reinterpret_cast<OPENSSL_STACK*>(sk.get()), elem.get()))
            CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failed to push element onto stack."); // LCOV_EXCL_LINE
    }

    template <typename StackT>
    raii::owned<typename raii::traits<typename StackT::type>::elem_type> pop(StackT& sk)
    {
        static_assert(raii::traits<typename StackT::type>::is_stack, "Requires OpenSSL RAII stack type!");

        return raii::owned<typename raii::traits<typename StackT::type>::elem_type> {
            reinterpret_cast<typename raii::traits<typename StackT::type>::elem_type*>(
                OPENSSL_sk_pop(reinterpret_cast<OPENSSL_STACK*>(sk.get())))
        };
    }

    template <typename StackT>
    class iterator
    {
    public:
        using iterator_type = iterator<StackT>;
        using elem_type = typename raii::traits<StackT>::elem_type;

        static iterator_type begin(raii::rwref<StackT> stack) noexcept
        {
            return iterator_type(stack);
        }

        static iterator_type end(raii::rwref<StackT> stack) noexcept
        {
            auto it = iterator_type(stack);
            it._index = stack::size(stack);
            return it;
        }

        iterator(iterator<StackT>&&) = default;
        iterator<StackT>& operator=(iterator<StackT>&&) = default;

        iterator(iterator<StackT> const&) = default;
        iterator<StackT>& operator=(iterator<StackT> const&) = default;

        ~iterator() = default;

        elem_type* operator*() noexcept
        {
            CPPOSSL_ASSERT(_index < stack::size(_stack));
            return stack::get(_stack, _index);
        }

        iterator_type& operator++() noexcept
        {
            _index = std::min(_index + 1, stack::size(_stack));
            return *this;
        }

        bool operator==(iterator_type const& Rhs) noexcept
        {
            return _stack.get() == Rhs._stack.get() && _index == Rhs._index;
        }

        bool operator!=(iterator_type const& Rhs) noexcept
        {
            return _stack.get() != Rhs._stack.get() || _index != Rhs._index;
        }

    private:
        iterator(raii::rwref<StackT> stack)
            : _stack(stack)
        {
        }

        raii::rwref<StackT> _stack;
        size_t _index { 0 };
    };

    template <typename StackT>
    stack::iterator<StackT> begin(raii::owned<StackT> const& stack) noexcept
    {
        return stack::iterator<StackT>::begin(stack);
    }

    template <typename StackT>
    stack::iterator<StackT> end(raii::owned<StackT> const& stack) noexcept
    {
        return stack::iterator<StackT>::end(stack);
    }

    template <typename StackT>
    stack::iterator<StackT> begin(raii::rwref<StackT> stack) noexcept
    {
        return stack::iterator<StackT>::begin(stack);
    }

    template <typename StackT>
    stack::iterator<StackT> end(raii::rwref<StackT> stack) noexcept
    {
        return stack::iterator<StackT>::end(stack);
    }

    /**@}*/

} // namespace stack

} // namespace ossl
