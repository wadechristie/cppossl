//
// Copyright (c) Microsoft Corporation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <array>

#include <cppossl/pem.hpp>

#include "common.hpp"

namespace ossl {
namespace unittest {

    namespace _ {

        static std::array<std::string_view, 3> constexpr static_keys = {
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzjpIplAVUDEzw\n"
            "rEU+ClPrcCI2zF91Z2vrvaBwzlojEb6txi7+5RagWgyyk33ke/xgxg8ZEvdesvIW\n"
            "HaP1G8wN18sHO1w/jLFPhywJaac5mfhPJPHlnGpdg/7lf7FFkwSW80sYyd8aloMq\n"
            "tQeMxqvqEdWf8m3wokdAwleZc/foGqhQqz9d8KZZiOri5bDuDjsvdtTBlndhUamn\n"
            "gPzy0veAaobwbqOONWQ2mXSkmsFHr7Vmg1CL+ZeDr8lFkGOX75MQn/Dw27b8A9+R\n"
            "1OuCrdzU2WM4RqDmhEAFPpOoYpG5F1sl6gbPNSKARu2ScjnpKCnFZc8bmqzbAN1J\n"
            "qa5GM2wTAgMBAAECggEARhgyFukh612h65JUtZNyj0aHFL1TxpFJIA42w9LKfUZA\n"
            "GbZ0Qi1MV+zPaCcLzlZYf67R1ggBaYaR2vBXQShI0F6dc4VIzcYusc0i88m67lGd\n"
            "DchuZiRZoYgVyaG/ollyQTtY5aRo5Ag9zD4/ZEVqd0XfD0GkiXvQNQepCs6qyIB3\n"
            "ylgoD80omdHh7EiJ+hjGAMSgGt9JUz2oNRG0ISSFEudHEY54nV4fBYcksmP63T6A\n"
            "t3k6UpnrZk8fyeyl65qrdMVIPbALWJjQ2DJXgawAO/B/IROiO94oUIo1UwzoanSL\n"
            "y0dFw9eFOstkojcY877NERb6mwjChqqhXDUbTq9ZgQKBgQDlqL+IpiMxbvGr8B4U\n"
            "Oy/lPiPAqbktQ2Y9YixP+LbJOj/bhhZw3X5Nm0hyvlT8E/ERRhuCUpLBR1HgUOeQ\n"
            "L1DAjA6oSQMlwnQ1G/VV++lLYMTh77+PQDiFhMp/rl8cnhGAaZ8GqGEzhvV3qoIT\n"
            "NjxwO3MJbRk+MYpDLllRy1JXHwKBgQDIJrh1KEz47dkW8RL04zDyQ9RuPA2ZBVq8\n"
            "7xkGw7/mopS3VaLc6xWVXpOqtazm+JL0RuPdebgwDLY5ZT7XVB8m5WuwsOOGF2sR\n"
            "jgQ//iraYS5UmYK2jsHXLDcua6mGzZCZQaAp05pd5muQBrhTGSWsQGwC0dqh5lRr\n"
            "m/g7JCiQjQKBgAWe77Ekf9AB6yBOLC5KlI2Dy9Q3UzTsZWAzOupqJ+8c4ds5mOsC\n"
            "QMkdd9R3HBVfV5MYqCu0YashV7upv0EkJ1HPG7y6rL0L2VRDbum/1KHnqGnvOD0F\n"
            "UVzTNzGQzvsgU0VVUHMVQ+vC7dcT8UMPHMOScOpWJTwEcmHajI0X8Nf5AoGBAIC6\n"
            "FoyTPN4k6yiMJ+sEa6iE4416Zixyeydkh64IG9YT3p4DH9oCAEGvMD3s1qU+XhVp\n"
            "uofpDwMoSdKkQURwQBDeIOLlAZBuY1hJBIa7y4fkVM3oZV9QdW8UavEaIVAnycYn\n"
            "pQEBrRiTZ76b89TOKaKdVFqD6Z+S6dzD1WUEHmrJAoGAWapfqpdlJt7MqXkPIDHb\n"
            "hC8wWZ7qNY4ftaDWTNHDGy+C0hFkkhyKBQ6/ZGXR3GIIcSLxWbHppBQzQwJOq2oD\n"
            "bCxjrSi89vIOz5rQ+gdfrnM9gozVc8gBjgJH5uj8yagsCAlztpJYZ0DSIxOcFdvS\n"
            "cOuJBLX75CwVjGOAcFYBKaA=\n"
            "-----END PRIVATE KEY-----\n",
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2Rqegbx4PXx7Q\n"
            "/69CmRELSPnEO/UpVaYwu9V61k/vC7eLoBwkRMSyETBf++ETUIvoCVnCpUpVG+0E\n"
            "IECYMjCVOOZefi/JSJzB8m+sXN/VlFd9h+vuKQhcg/jfRUexudIwljOi1crW9p2S\n"
            "FQS0xGmXoLSF8XwpwsRmKL8vDNhrsOqgaIGAMKcMF5nVz9H8SIO0n1EOD38+tWFI\n"
            "PckQ8P+PIY5PyM83nZnAsd4kAy9PjfMPG8TXworkwbAuWK+2YNO6C6bdl5Tvj9j9\n"
            "5wGNyodXfusr7rPyW+BdfUX47o4RglasDXTVrONlFBZWuRfgDNLpc5fOS3MH+D+b\n"
            "NKFGQ/CtAgMBAAECggEAT1K7M0H4IndiOVD0C/cB6FfXPjNbkyPvYYj0s/LdMWn3\n"
            "c/93D7+Pm/CIDVVXk2i7ofyjv+Xfzd8Ly/5fLfy1kNMEyf1/PUjo0yx2tdtrG47l\n"
            "bj8/CNN5jI1wOnXzZ+A2nSdYjFYe4mLLmt2jwSkyzKZGuX2oa6ITh2PXI5oi+uX0\n"
            "c4pyXOvocNOScH55eqQWaxVexOP8JyVqo8d+onHsX5+8AU8n1/6ccvdnyj44XYH7\n"
            "Kw4BhJo/AAiMrnnqcW0nCalRLn/o9N6PGO2gxd19I53rlEOAwIxep4PeorDLbKsK\n"
            "r6u4IFmP4dXfSQyBi2dK5znrWRF8yJ0wOWF+SBVYDwKBgQDep5T9/H9eOjbhSBAD\n"
            "OufY0p1rumLFx9dYsZkG8E1k11DPlg3tcwNbaF/+7gzn7lkb5fepjGr/rOdMev7k\n"
            "e728Mc8WQ1P0LBXaw+G6V8vk+/yiRUuE6qd8f5YwSf5oCMibWm8tCEOE3T+go7lr\n"
            "NqeQiTTbkJ4f6UqgbV3gGIHg/wKBgQDRkvxGTJ4qtAhSFUYu3o2x8ODHueVF21Sg\n"
            "Wld0CpR9i6zKXfLvht7X1qB8ZIZiDw83Sxh+2cMEXDkwAxaSxXxn2wcsKtOJPU2b\n"
            "Z84fkq2xboPbuWSm+vwMVXnq0D1axwM0wNKig2KEu72GZldQtl4JC8vD+5svfkFB\n"
            "iUxCCZoCUwKBgFaW16Oa4bG0dAlSrB+FdgrlhaESoD0IheARWVDQfVi9P8krMwlo\n"
            "FCMlSUfsLgq4r+Dgo1tFp4r9JAqjPqN+1//rYvzmfCzWRD2Ktitw33OS5+H3jvIH\n"
            "C9GoELGA5TZyTAnWtqvNrexq2sbPRVnDrJDSO0M0T7pbUNFpFvwCq+fjAoGABP3k\n"
            "RmRizA+XtyTMlCc25sse/4LdBCnyPROJy7jIyqi+B9/u/meO/UMedXgLf2Buc1m1\n"
            "jqfvLjZoIk2ghwRvLyYXaKTofvdX1uDFFxluS7CfMWecDyIhSMXsbnxhSb09xU7m\n"
            "dXp9qT2ziPT9FW4SlVKTmupuStZOBZqYl2YVJgMCgYEA2T3+lwjhDNPSiaBjGk1f\n"
            "4gECsVuZ4xJYdK06bjNVpSYomQzj+PsnC/rycsE85cGpp2pG0bEa2zT2+xa/qGVe\n"
            "FWDCHJY0WL6lz2Jj7E5105I+2JiXjVqJG9OKhzlyUhh9EWDMD1+nctZcyxhjEy7H\n"
            "+rSqiAjV5NxIAhF2wVV0ZyU=\n"
            "-----END PRIVATE KEY-----\n",
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwKRa/ThFUsNu0\n"
            "g8tDus1euXNj0eM8fMBRq1GlolgTMhPNFAKoSyf5wPI0P9Fx6X7C2isFtFqjiqt9\n"
            "Ovu0snxUukFt/o4+kepXAn2l1yTTp6TrEbMuFYdF4FHOVuKi2MHmCqy6jWtGk5+a\n"
            "SdFjNW9nW9RenjiHM3eqhBCnCk2tYCvNSUwGNs+DDkNjZ9KVp8IbWO0lQ/8kjO9u\n"
            "VoSRqnv9urevUb6VdlrS/DM9jGLJDGMyx1YXpyPtiOQCZwdgxjziys5/DjUwwOxo\n"
            "pmPDP2+Wx1WpPLYs2zgUCvVmY0kSUrtW5LwK25gjZl6euAisnP9bIl2QTQyxanrx\n"
            "EMiLZh6NAgMBAAECggEAT3GgUBMRbsu5sX10SC2w24Sv/LbVj1xFUS99SUDfDn0Z\n"
            "f/WDw0jtlM1GjXiwaHpgT9ia6V4uOC3b68STaijKOF2tD0Fq/d3JPIcjigxuD8O9\n"
            "dMONNn2//SvOSMtXNxCg1TFAN3t6gyAlLKwYsXCSNp8rtaYOIS79Sxl29xYG9OY1\n"
            "9YzEsM38uMY2cVs+37zCj6f5tBqx1SEHdNOY+VLZZfi3gI3inUqmIrDrAGAicIYG\n"
            "jkygBPo/1n68+CLO1GcJ1iv3Yv4+7moMBREFxMGXpEXWLU3gcANVcstr720tLrwt\n"
            "jKZ60U6iZfOqdri7w/vutIejVAwwPxxkamRFgUFRkwKBgQD2ywpDnSNxcWThWg8b\n"
            "uppbbaPy3mEI2ZLSXKuVZ/BY0i8TiiBi6nw7uGvBXIA5Mam9OjE81S7SlWAdxQoh\n"
            "6gm6ZTe1cfAx4LCXBAuOlHbF7r52ju/hZUesJ8TOght/owxGL2HCaucHKKAy5lVe\n"
            "8tt+nGbcCppfvARGpMJOmZEkawKBgQC2u3uUhnwc4QXJwU0syNKcm1kkvFgSn1WO\n"
            "8xdvtibRWWQEw4z/QUbBmjgvYYMLpYacY29kJ/5GwxQJ5IxMMZiBY4AW3VEQw0/V\n"
            "NTvYkSoPTETObYRDhjr5AKkP1wpDFq43t/ZIqzLXiogC0z08bA8YytanIS72tcqC\n"
            "slxuYqtG5wKBgQCG0tdxprgFMpiVEBku4duP1S768If8SLiQGbZXMeg47eJv/0bA\n"
            "Iy/phE/B2+Hk3P/I87CQdjpVKuvOd6WYb34PCVrM0kkRRpnSdpBFvU/BxDLjHCVq\n"
            "cmUcZMF8u9GAAjgjY6E5kCNUYtpZ1EGRVIWa/qCm11gMsu93FG1eeUC0rwKBgFX+\n"
            "oUfiimIk285489LRp5wf17HcGS6aYW9mo27lMBtxkApV5PLzS1MtOqfBoiRG/7R1\n"
            "bySZVacDg1isgAITjQvHQa6A9PeIkvdpmAJxPnP4lqD3FTmZ4ALy9p0HvEKaV97M\n"
            "6lCEkOaywRNjSfw3dltaie4ZRbrBDs63FZy1PpmdAoGAJmfoto8YTI/pVxbm1XbY\n"
            "97sswngTtZhurxLhBKHz4JF3osQ2BAJlbdh1pbM0seKMrHL8RP0dOFqmxjzNYNcY\n"
            "KiBvV5kH0aPj5PYeKk+MAmGIw/sxDdEL2ZUNtsYV++DLtPlR8wZ50rZkZRYFjLWz\n"
            "udGRoN5lCsh7FHdf+MvNr+A=\n"
            "-----END PRIVATE KEY-----\n",
        };

    } // namespace _

    // std::vector<std::string> get_test_pkey_data()
    // {
    //     return std::vector<std::string> { _::static_keys.begin(), _::static_keys.end() };
    // }

    std::string test_pkey::pem() const
    {
        return std::string { _::static_keys.at(index) };
    }

    owned<::EVP_PKEY> test_pkey::load() const
    {
        return pem::load<::EVP_PKEY>(pem());
    }

} // namespace  unittest
} // namespace ossl
