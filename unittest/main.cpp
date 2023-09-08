//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <catch2/catch_session.hpp>

int main(int argc, char* argv[])
{
    Catch::Session session;
    int rc = session.applyCommandLine(argc, argv);
    if (rc != 0)
        return rc;

    return session.run();
}
