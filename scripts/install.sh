#!/bin/bash

# PacketPanther Installation Script
# This script installs the latest version of PacketPanther

set -e

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

# Map architecture to Go arch
case "${ARCH}" in
  x86_64)
    GOARCH="amd64"
    ;;
  arm64|aarch64)
    GOARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: ${ARCH}"
    exit 1
    ;;
esac

# Get the latest version
VERSION=$(curl -s https://api.github.com/repos/Samirrahman71/PacketPanther/releases/latest | grep -E 'tag_name' | cut -d '"' -f 4)

if [ -z "${VERSION}" ]; then
  echo "Error: Failed to get the latest version"
  exit 1
fi

echo "Installing PacketPanther ${VERSION} for ${OS}/${GOARCH}..."

# Set download URL
DOWNLOAD_URL="https://github.com/Samirrahman71/PacketPanther/releases/download/${VERSION}/ppanther-${OS}-${GOARCH}"
if [ "${OS}" = "windows" ]; then
  DOWNLOAD_URL="${DOWNLOAD_URL}.exe"
fi

# Set installation directory
INSTALL_DIR="/usr/local/bin"
if [ "${OS}" = "darwin" ]; then
  # Check if Homebrew is installed and use its prefix
  if command -v brew >/dev/null 2>&1; then
    INSTALL_DIR="$(brew --prefix)/bin"
  fi
elif [ "${OS}" = "windows" ]; then
  INSTALL_DIR="${HOME}/bin"
fi

# Create installation directory if it doesn't exist
mkdir -p "${INSTALL_DIR}"

# Download and install
echo "Downloading from ${DOWNLOAD_URL}..."
curl -L -o "${INSTALL_DIR}/ppanther" "${DOWNLOAD_URL}"
chmod +x "${INSTALL_DIR}/ppanther"

echo "PacketPanther has been installed to ${INSTALL_DIR}/ppanther"

# Check if the directory is in PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
  echo
  echo "NOTE: ${INSTALL_DIR} is not in your PATH. You may need to add it to your shell profile:"
  echo "  export PATH=\$PATH:${INSTALL_DIR}"
  echo
fi

echo "To run PacketPanther, simply type: ppanther"
echo "For help and options, type: ppanther --help"
echo
echo "🐆 Happy packet hunting!"
