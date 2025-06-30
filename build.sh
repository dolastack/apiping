#!/bin/bash

set -e

BINARY=apiping
VERSION=$(date +"%Y%m%d")

echo "Building version: $VERSION"

# Clean old builds
rm -rf dist/
mkdir -p dist/

# Get GOOS and GOARCH
PLATFORMS=("linux/amd64" "darwin/amd64" "windows/amd64")

for PLATFORM in "${PLATFORMS[@]}"
do
    GOOS=${PLATFORM%/*}
    GOARCH=${PLATFORM##*/}
    OUTPUT_NAME=$BINARY-$VERSION-$GOOS-$GOARCH
    if [ "$GOOS" = "windows" ]; then
        OUTPUT_NAME+=".exe"
    fi

    echo "Building for $GOOS/$GOARCH..."
    CGO_ENABLED=0 go build -o dist/$OUTPUT_NAME
done

echo "Build complete. Binaries are in ./dist/"