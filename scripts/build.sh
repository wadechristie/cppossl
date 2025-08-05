#!/bin/bash

source "$(dirname "$0")/config"
source "$(dirname "$0")/common"

function show_usage()
{
    echo "CMake build helper."
    echo ""
    echo "Usage:"
    echo "  build.sh [OPTIONS]"
    echo ""
    echo "  Options:"
    echo "    --help            Show this help."
    echo "    --clean           Cleanup the build directory and rebuild everything from scratch."
    echo "    --deep-clean      Reconfigure and build everything from scratch."
    echo "    --asan            Building w/ ASAN."
    echo "    --clang           Build w/ Clang."
    echo "    --docs            Build doxygen documentation."
    echo "    --release         Configure for release."
    echo "    --builddir        Build directory path."
    echo "    --configure       Only perform cmake configuration."
}

EXTRA_PARAMS=()

DO_BUILD="yes"
DO_DEEP_CLEAN="no"
DO_CLEAN="no"
DO_RELEASE="no"
USE_CLANG="no"
WITH_ASAN="no"
WITH_COVERAGE="no"
WITH_DOCS="no"

while (( "$#" )); do
    case "$1" in

        --asan)
            WITH_ASAN="yes"
            shift
            ;;

        --builddir)
            BUILD_DIR="$2"
            shift 2
            ;;

        --clean)
            DO_CLEAN="yes"
            shift
            ;;

        --deep-clean)
            DO_DEEP_CLEAN="yes"
            shift
            ;;

        --clang)
            USE_CLANG="yes"
            shift
            ;;

        --configure)
            DO_BUILD="no"
            shift
            ;;

        --coverage)
            WITH_COVERAGE="yes"
            WITH_ASAN="no"
            USE_CLANG="no"
            shift
            ;;

        --docs)
            WITH_DOCS="yes"
            shift
            ;;

        --release)
            DO_RELEASE="yes"
            shift
            ;;

        --help)
            show_usage
            exit 0
            ;;

        *)
            die "Unsupported flag: $1"
            # EXTRA_PARAMS=("${EXTRA_PARAMS[@]}" "$1")
            # shift
            ;;
    esac
done

# Deep clean
if [[ 'yes' == "${DO_DEEP_CLEAN}" ]] && [[ -e "${BUILD_DIR}" ]]
then
    header 'Deep Clean'
    rm -rf "${BUILD_DIR}"
    echo 'Done!'
fi

# Build
header 'Build'
if [[ ! -e "${BUILD_DIR}" ]]
then
    mkdir "${BUILD_DIR}" || die 'Failed to make build directory!'
    pushd "${BUILD_DIR}" || die 'pushd failed!'

    cmake_args=(-DCMAKE_EXPORT_COMPILE_COMMANDS=ON "-DCMAKE_INSTALL_PREFIX='${STAGE_DIR}'" "-DCPPOSSL_BuildTests=ON")

    case "${DO_RELEASE}" in
        'yes')
            cmake_args=("${cmake_args[@]}" "-DCMAKE_BUILD_TYPE=RELEASE")
            ;;

        *)
            cmake_args=("${cmake_args[@]}" "-DCMAKE_BUILD_TYPE=DEBUG")
            ;;
    esac

    case "${USE_CLANG}" in
        'yes')
            [[ 'yes' == "${WITH_COVERAGE}" ]] && die 'Cannot use --clang w/ --coverage!'
            cmake_args=("${cmake_args[@]}" "-DCMAKE_C_COMPILER=${CLANG_C}" "-DCMAKE_CXX_COMPILER=${CLANG_CXX}")
            ;;

        *)
            cmake_args=("${cmake_args[@]}" "-DCMAKE_C_COMPILER=${GCC_C}" "-DCMAKE_CXX_COMPILER=${GCC_CXX}")
            ;;
    esac

    case "${WITH_ASAN}" in
        'yes')
            [[ 'yes' == "${WITH_COVERAGE}" ]] && die 'Cannot use --asan w/ --coverage!'
            cmake_args=("${cmake_args[@]}" -DCPPOSSL_UseASAN=ON)
            ;;

        *)
            ;;
    esac

    case "${WITH_COVERAGE}" in
        'yes')
            cmake_args=("${cmake_args[@]}" -DCPPOSSL_UseGcov=ON -DCPPOSSL_UseASAN=OFF)
            ;;

        *)
            ;;
    esac

    echo "cmake ${cmake_args[@]} .."
    cmake "${cmake_args[@]}" .. || die 'cmake error!'
    popd || die 'popd failed!'
fi

# Build
if [[ 'yes' == "${DO_BUILD}" ]]
then
    pushd "${BUILD_DIR}" || die 'pushd failed!'
    if [[ 'yes' == "${DO_CLEAN}" ]]
    then
        cmake --build . --target clean || die 'Clean Error!'
    fi
    cmake --build . -- -j$(nproc) || die 'Build Error!'
    if [[ 'yes' == "${WITH_DOCS}" ]]
    then
        cmake --build . --target docs || die 'Build Docs Error!'
    fi
    popd || die 'popd failed!'
fi

exit 0
