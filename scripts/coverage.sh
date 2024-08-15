#!/bin/bash

source "$(dirname "$0")/config"
source "$(dirname "$0")/common"

function show_usage()
{
    echo "Code coverage helper."
    echo ""
    echo "Usage:"
    echo "  coverage.sh [--help]"
    echo ""
    echo "  Options:"
    echo "    --help      Show this help."
}

DO_CLEAN="no"
EXTRA_PARAMS=()
BUILD_PARAMS=("--coverage" "--builddir" "${COV_DIR}")

while (( "$#" )); do
    case "$1" in
        --help)
            show_usage
            exit 0
            ;;
        --clean)
            DO_CLEAN="yes"
            shift
            ;;
        *)
            die "Unsupported flag: $1"
            ;;
    esac
done

if [[ 'yes' == "${DO_CLEAN}" ]]
then
    BUILD_PARAMS=("--clean" "${BUILD_PARAMS[@]}")
fi

echo "./scripts/build.sh ${BUILD_PARAMS[@]}"
./scripts/build.sh "${BUILD_PARAMS[@]}" || die 'Build failed!'


header 'Execute Tests'
pushd "${COV_DIR}" || die 'pushd failed!'

./unittest/cppossl-unittest

header 'Gather Coverage Data'
find -name '*.gcno' | xargs -I{} gcov {}
lcov --capture --directory . --output-file coverage.info || exit 1
# Prune coverage data to just relevant library data
lcov -r coverage.info "/usr*" -o coverage.info
lcov -r coverage.info "${COV_DIR}/_deps/*" -o coverage.info
lcov -r coverage.info "${PROJECT_DIR}/unittest/*" -o coverage.info

header 'Generate Report'
genhtml coverage.info --no-prefix --output-directory "./report"

header 'Serve Report'
python3 -m http.server --bind "127.0.0.1" --directory "./report"

exit 0
