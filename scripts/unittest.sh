#!/bin/bash

source "$(dirname "$0")/config"
source "$(dirname "$0")/common"

function show_usage()
{
    echo "Unittest helper."
    echo ""
    echo "Usage:"
    echo "  unittest.sh [--help] [--clean] [--gdb]"
    echo ""
    echo "  Options:"
    echo "    --clean       Cleanup the build directory and rebuild everything from scratch."
    echo "    --gdb         Run tests under gdb debugger."
    echo "    --valgrind    Execute tests under valgrind."
    echo "    --help        Show this help."
}

EXTRA_PARAMS=()
BUILD_PARAMS=()
DO_GDB="no"
DO_VG="no"
TSUITE="${BUILD_DIR}/unittest/cppossl-unittest"

while (( "$#" )); do
    case "$1" in
        --clean)
            BUILD_PARAMS=("${BUILD_PARAMS[@]}" "--clean")
            shift
            ;;
        --gdb)
            DO_GDB="yes"
            EXTRA_PARAMS=("${EXTRA_PARAMS[@]}" "--break")
            shift
            ;;
        --valgrind)
            DO_VG="yes"
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            EXTRA_PARAMS=("${EXTRA_PARAMS[@]}" "$1")
            shift
            ;;
    esac
done

./scripts/build.sh "${BUILD_PARAMS[@]}" || exit 1

if [[ 'yes' == "${DO_GDB}" ]]
then
    gdb --args "${TSUITE}" "${EXTRA_PARAMS[@]}"
elif [[ 'yes' == "${DO_VG}" ]]
then
    valgrind --leak-check=full "${TSUITE}" "${EXTRA_PARAMS[@]}"
else
    "${TSUITE}" "${EXTRA_PARAMS[@]}"
fi

exit 0
