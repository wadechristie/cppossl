cmake_minimum_required(VERSION 3.18)

##
## PROJECT
##

project(cppossl VERSION 1.0.2 LANGUAGES CXX C)

##
## MAIN_PROJECT CHECK
##

set(MAIN_PROJECT OFF)
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(MAIN_PROJECT ON)
endif()

##
## OPTIONS
##

if(${MAIN_PROJECT})
    set(CPPOSSL_BuildTests_INIT         ON)
    set(CPPOSSL_BuildDocs_INIT          ON)
else()
    set(CPPOSSL_BuildTests_INIT         OFF)
    set(CPPOSSL_BuildDocs_INIT          OFF)
endif()

option(CPPOSSL_BuildTests       "Build the unittests."          ${CPPOSSL_BuildTests_INIT})
option(CPPOSSL_BuildDocs        "Build the documentation."      ${CPPOSSL_BuildDocs_INIT})
option(CPPOSSL_BuildTools       "Build the tools directory."    ON)
option(CPPOSSL_UseASAN          "Build w/ address sanitizer."   OFF)
option(CPPOSSL_UseGcov          "Build w/ code coverage."       OFF)

##
## CONFIGURATION
##

if(${MAIN_PROJECT})
    set(CMAKE_CXX_STANDARD 17)

    include(FetchContent)
endif()

##
## Address Sanitizer
##

if (MAIN_PROJECT AND CPPOSSL_UseASAN AND NOT CERTIFY_UseGcov)
    message(AUTHOR_WARNING "CPPOSSL_UseASAN: ON - Building w/ ASAN flags '-fsanitize=address -fno-omit-frame-pointer -fsanitize=undefined -fno-sanitize-recover=all'")
    add_compile_options(
        -fsanitize=address -fno-omit-frame-pointer
        -fsanitize=undefined -fno-sanitize-recover=all
    )
    link_libraries(
        -fsanitize=address -fno-omit-frame-pointer
        -fsanitize=undefined -fno-sanitize-recover=all
    )
endif()

##
## Code Coverage
##

if (MAIN_PROJECT AND CPPOSSL_UseGcov)
    message(AUTHOR_WARNING "CPPOSSL_UseGcov: ON - Building w/ code coverage")
    add_compile_options(-fprofile-arcs -ftest-coverage)
    link_libraries(gcov)
endif()

##
## Library
##

SET(CPPOSSL_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asn1_time.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bio.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/error.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/evp_pkey.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/general_name.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pem.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_builder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_crl_builder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_crl.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_extension.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_name.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_req_builder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_req.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/x509_store.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/x509.cpp
)

SET(CPPOSSL_INC
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/asn1_time.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/bio.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/error.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/evp_pkey.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/general_name.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/pem.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/raii.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/stack.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/x509_builder.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/x509_crl_builder.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/x509_crl.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/x509_extension.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/x509_name.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/x509_req_builder.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/x509_req.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/x509_store.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cppossl/x509.hpp
)

add_library(cppossl ${CPPOSSL_INC} ${CPPOSSL_SRC})
add_library(cppossl::cppossl ALIAS cppossl)
target_compile_features(cppossl PUBLIC cxx_std_17)
target_compile_options(cppossl PRIVATE -Wall -Werror)
target_link_libraries(cppossl PUBLIC crypto)

target_include_directories(cppossl
PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/>)

install(
    TARGETS cppossl
    DESTINATION lib
)
install(
    FILES ${CPPOSSL_INC}
    DESTINATION include/cppossl
)

##
## TESTS
##

if (CPPOSSL_BuildTests)
    if(NOT TARGET Catch2::Catch2)
        # Import catch2 library
        FetchContent_Declare(
            Catch2
            GIT_REPOSITORY https://github.com/catchorg/Catch2.git
            GIT_TAG        6e79e682b726f524310d55dec8ddac4e9c52fb5f # v3.4.0
        )

        FetchContent_MakeAvailable(Catch2)
    endif()

    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
    include(Catch)
    enable_testing()
    add_subdirectory(unittest)
endif()

##
## Tools
##

if (CPPOSSL_BuildTools)
    add_subdirectory(tools)
endif()

##
## Docs
##

if (CPPOSSL_BuildDocs)
    find_package(Doxygen)
    if (DOXYGEN_FOUND)
        # set input and output files
        set(DOXYGEN_IN ${PROJECT_SOURCE_DIR}/docs/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

        # request to configure the file
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        message("Doxygen build started")

        # note the option ALL which allows to build the docs together with the application
        add_custom_target(docs
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM)
    else (DOXYGEN_FOUND)
        message("Doxygen need to be installed to generate the doxygen documentation")
    endif (DOXYGEN_FOUND)
endif()
