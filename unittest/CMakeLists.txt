cmake_minimum_required(VERSION 3.18)

##
## UNITTEST
##

# list of sources files of the library
SET(CPPOSSL_UNITTEST_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/common_pkeys.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_asn1_bit_string.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_asn1_time.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_bio.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_evp_pkey.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_openssl_error.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_stack.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_x509_builder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_x509_crl_builder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_x509_crl.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_x509_name.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_x509_req_builder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_x509_req.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_x509_store.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_x509.cpp
)

add_executable(cppossl-unittest ${CPPOSSL_UNITTEST_SRC})
target_compile_features(cppossl-unittest PUBLIC cxx_std_17)
target_compile_options(cppossl-unittest PRIVATE -Wall -Werror)
target_link_libraries(cppossl-unittest Catch2::Catch2 cppossl)

catch_discover_tests(cppossl-unittest)

