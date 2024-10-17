//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <new>

#include <openssl/stack.h>

#include <cppossl/raii.hpp>

namespace ossl {
namespace sk {

    template <typename T>
    class stack_iterator;

    template <typename T>
    class stack_wrapper
    {
    public:
        typedef typename raii::traits<T>::stack_type* raw_stack_ptr;

        stack_wrapper() = delete;

        explicit stack_wrapper(raw_stack_ptr sk)
            : _sk(reinterpret_cast<OPENSSL_STACK*>(sk))
        {
        }

        stack_wrapper(stack_wrapper&&) = delete;
        stack_wrapper& operator=(stack_wrapper&&) = delete;

        stack_wrapper(stack_wrapper const&) = delete;
        stack_wrapper& operator=(stack_wrapper const&) = delete;

        ~stack_wrapper()
        {
        }

        size_t size() const
        {
            return OPENSSL_sk_num(_sk);
        }

        bool empty() const
        {
            return size() == 0;
        }

        void push(raii::owned<T> value)
        {
            if (OPENSSL_sk_push(_sk, value.get()) <= 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                    "Failure occurred attempting to push stack element.");
            (void)value.release();
        }

        void unshift(raii::owned<T> value)
        {
            if (OPENSSL_sk_unshift(_sk, value.get()) <= 0)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                    "Failure occurred attempting to unshift stack element.");
            (void)value.release();
        }

        raii::owned<T> pop()
        {
            void* v = OPENSSL_sk_pop(_sk);
            if (v == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR("Failure occurred attempting to pop stack element."); // LCOV_EXCL_LINE
            return raii::owned<T>(reinterpret_cast<T*>(v));
        }

        raii::owned<T> shift()
        {
            void* v = OPENSSL_sk_shift(_sk);
            if (v == nullptr)
                CPPOSSL_THROW_LAST_OPENSSL_ERROR( // LCOV_EXCL_LINE
                    "Failure occurred attempting to shift stack element.");
            return raii::owned<T>(reinterpret_cast<T*>(v));
        }

        stack_iterator<T> begin() noexcept
        {
            return stack_iterator<T>(_sk, 0);
        }

        stack_iterator<T> end() noexcept
        {
            return stack_iterator<T>(_sk, size());
        }

        raw_stack_ptr raw() const
        {
            return reinterpret_cast<raw_stack_ptr>(_sk);
        }

        void drop()
        {
            _sk = nullptr;
        }

        raw_stack_ptr release()
        {
            auto sk = raw();
            drop();
            return sk;
        }

    protected:
        explicit stack_wrapper(OPENSSL_STACK* sk)
            : _sk(sk)
        {
        }

        OPENSSL_STACK* _sk { nullptr };
    };

    template <typename T>
    stack_wrapper<typename raii::traits<T>::elem_type> wrap(T* sk)
    {
        return stack_wrapper<typename raii::traits<T>::elem_type>(sk);
    }

    template <typename T>
    stack_wrapper<typename raii::traits<T>::elem_type> wrap(raii::owned<T> const& sk)
    {
        return wrap(sk.get());
    }

    template <typename T>
    class owned_stack : public stack_wrapper<T>
    {
    public:
        typedef raii::owned<typename raii::traits<T>::stack_type> owned_handle;

        static owned_stack<T> make()
        {
            OPENSSL_STACK* sk = OPENSSL_sk_new_null();
            if (sk == nullptr)
                throw std::bad_alloc(); // LCOV_EXCL_LINE
            return owned_stack<T>(sk);
        }

        explicit owned_stack(typename raii::traits<T>::stack_type* stack)
            : stack_wrapper<T>(stack)
        {
        }

        explicit owned_stack(owned_handle stack)
            : stack_wrapper<T>(stack.get())
        {
            (void)stack.release();
        }

        owned_stack(owned_stack&& move) noexcept
        {
            std::swap(this->_sk, move._sk);
        }

        owned_stack& operator=(owned_stack&& move) noexcept
        {
            std::swap(this->_sk, move._sk);
            return *this;
        }

        owned_stack(owned_stack const&) = delete;
        owned_stack& operator=(owned_stack const&) = delete;

        ~owned_stack()
        {
            if (this->_sk != nullptr)
            {
                OPENSSL_sk_pop_free(this->_sk, reinterpret_cast<OPENSSL_sk_freefunc>(raii::traits<T>::freefn));
                this->_sk = nullptr;
            }
        }

        owned_handle mine()
        {
            return owned_handle(this->release());
        }

    private:
        owned_stack(OPENSSL_STACK* sk)
            : stack_wrapper<T>(sk)
        {
        }
    };

    template <typename T>
    class stack_iterator
    {
    public:
        stack_iterator() = delete;

        stack_iterator(stack_iterator&&) = default;
        stack_iterator& operator=(stack_iterator&&) = default;

        stack_iterator(stack_iterator const&) = default;
        stack_iterator& operator=(stack_iterator const&) = default;

        ~stack_iterator() = default;

        T* operator*() noexcept
        {
            return reinterpret_cast<T*>(OPENSSL_sk_value(_sk, _pos));
        }

        stack_iterator& operator++() noexcept
        {
            _pos = std::min(_pos + 1, static_cast<size_t>(OPENSSL_sk_num(_sk)));
            return *this;
        }

        bool operator==(stack_iterator const& Rhs) noexcept
        {
            return _sk == Rhs._sk && _pos == Rhs._pos;
        }

        bool operator!=(stack_iterator const& Rhs) noexcept
        {
            return _sk != Rhs._sk || _pos != Rhs._pos;
        }

    private:
        stack_iterator(OPENSSL_STACK* sk, size_t pos) noexcept
            : _sk(sk)
            , _pos(pos)
        {
        }

        friend class stack_wrapper<T>;

        OPENSSL_STACK* _sk { nullptr };
        size_t _pos { 0 };
    };

    template <typename T>
    owned_stack<T> make()
    {
        return owned_stack<T>::make();
    }

    template <typename T>
    owned_stack<typename raii::traits<T>::elem_type> make(raii::owned<T> sk)
    {
        return owned_stack<typename raii::traits<T>::elem_type>(std::move(sk));
    }

    template <typename T>
    owned_stack<typename raii::traits<T>::elem_type> make(T* sk)
    {
        return owned_stack<typename raii::traits<T>::elem_type>(sk);
    }

} // namespace sk
} // namespace ossl
