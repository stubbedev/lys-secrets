#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "Usage: $0 <bin-dir> <version> <arch>" >&2
	exit 1
fi

BIN_DIR="$(readlink -f "$1")"
VERSION="$2"
ARCH="$3"

cd "$(dirname "$0")/../.."

STAGING="lys-secrets-${VERSION}-${ARCH}-linux"
rm -rf "${STAGING}"
mkdir -p "${STAGING}"
cp "${BIN_DIR}/lys-secrets" LICENSE \
	resources/lys-secrets.service \
	resources/org.freedesktop.secrets.service \
	"${STAGING}/"
tar czf "${STAGING}.tar.gz" "${STAGING}"
rm -rf "${STAGING}"
