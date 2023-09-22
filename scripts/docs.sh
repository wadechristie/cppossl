#!/bin/bash

source "$(dirname "$0")/config"
source "$(dirname "$0")/common"

function show_usage()
{
    echo "Documentation viewer."
    echo ""
    echo "Usage:"
    echo "  docs.sh [--help]"
    echo ""
    echo "  Options:"
    echo "    --help      Show this help."
}

EXTRA_PARAMS=()
BUILD_PARAMS=("--docs")

while (( "$#" )); do
    case "$1" in
        --help)
            show_usage
            exit 0
            ;;
        *)
            die "Unsupported flag: $1"
            ;;
    esac
done

echo "./scripts/build.sh ${BUILD_PARAMS[@]}"
./scripts/build.sh "${BUILD_PARAMS[@]}"


header 'Start HTTP Server'
python3 -m http.server --bind "127.0.0.1" --directory "${BUILD_DIR}/doxygen/html"

exit 0
