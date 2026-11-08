#!/usr/bin/env bash
# Sign release checksums with GPG and/or cosign.
#
# Usage:
#   scripts/sign-release.sh [--gpg KEY_ID] [--cosign KEY_PATH]
#
# Environment fallbacks:
#   RAYSCAN_GPG_KEY     GPG key ID or fingerprint
#   RAYSCAN_COSIGN_KEY  cosign private key path
#
# Produces dist/SHA256SUMS.asc (GPG) and/or
# dist/SHA256SUMS.cosign.bundle (cosign).  Verification commands are printed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUMS="$ROOT/dist/SHA256SUMS"
GPG_KEY="${RAYSCAN_GPG_KEY:-}"
COSIGN_KEY="${RAYSCAN_COSIGN_KEY:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gpg)
      GPG_KEY="${2:?--gpg requires a key id}"
      shift 2
      ;;
    --cosign)
      COSIGN_KEY="${2:?--cosign requires a private key path}"
      shift 2
      ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$SUMS" ]]; then
  echo "missing $SUMS; run 'make dist' first" >&2
  exit 1
fi

signed=0

if [[ -n "$GPG_KEY" ]]; then
  command -v gpg >/dev/null 2>&1 || {
    echo "gpg is required for GPG signing" >&2
    exit 1
  }
  gpg --batch --yes --armor --detach-sign \
    --local-user "$GPG_KEY" \
    --output "$SUMS.asc" "$SUMS"
  echo "GPG signature: $SUMS.asc"
  echo "verify with: gpg --verify $SUMS.asc $SUMS"
  signed=1
fi

if [[ -n "$COSIGN_KEY" ]]; then
  command -v cosign >/dev/null 2>&1 || {
    echo "cosign is required for keyless signing" >&2
    exit 1
  }
  cosign sign-blob --yes --key "$COSIGN_KEY" \
    --bundle "$SUMS.cosign.bundle" "$SUMS"
  echo "cosign bundle: $SUMS.cosign.bundle"
  echo "verify with: cosign verify-blob --key <pub> --bundle $SUMS.cosign.bundle $SUMS"
  signed=1
fi

if [[ "$signed" -eq 0 ]]; then
  echo "no signing key configured; set RAYSCAN_GPG_KEY or RAYSCAN_COSIGN_KEY" >&2
  exit 1
fi
