//
// Copyright (c) Wade Christie and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#pragma once

#include <cppossl/general_name.hpp>
#include <cppossl/raii.hpp>
#include <cppossl/stack.hpp>

namespace ossl {
namespace x509 {
    namespace builder {
        namespace v2 {
            namespace subject_alt_names {

                class context
                {
                public:
                    context() = delete;

                    context(context&&) = delete;
                    context& operator=(context&&) = delete;

                    context(context const&) = delete;
                    context& operator=(context const&) = delete;

                    ~context() = default;

                    inline raii::roref<STACK_OF(GENERAL_NAME)> get() const
                    {
                        return { names };
                    }

                private:
                    owned<STACK_OF(GENERAL_NAME)> names;
                };

            } // namespace subject_alt_names
        } // namespace v2
    } // namespace builder
} // namespace x509
} // namespace ossl
