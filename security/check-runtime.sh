#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if command -v node >/dev/null 2>&1; then
  node "$root/runtime-security.cjs" --regression
fi
if command -v dpkg-query >/dev/null 2>&1; then
  if dpkg-query -W -f='${db:Status-Status}' libbrotli1 2>/dev/null | grep -qx installed; then
    version=$(dpkg-query -W -f='${Version}' libbrotli1)
    . /etc/os-release
    case "${VERSION_CODENAME:-}" in
      bookworm) minimum=1.0.9-2+deb12u1 ;;
      trixie) minimum=1.1.0-2+deb13u1 ;;
      *) minimum=1.2.1 ;;
    esac
    dpkg --compare-versions "$version" ge "$minimum" || {
      echo "CVE-2026-111497: libbrotli1 $version is below $minimum" >&2; exit 1;
    }
    echo "Native Brotli gate passed: $version"
  fi
elif command -v apk >/dev/null 2>&1; then
  if apk info -e brotli-libs >/dev/null 2>&1; then
    version=$(apk list --installed 2>/dev/null | sed -n 's/^brotli-libs-\([^ ]*\) .*/\1/p')
    test -n "$version"
    test "$(apk version -t "$version" 1.2.1-r0)" != '<' || {
      echo "CVE-2026-111497: brotli-libs $version is below 1.2.1-r0" >&2; exit 1;
    }
    echo "Native Brotli gate passed: $version"
  fi
else
  echo "Cannot verify native Brotli packages: unsupported image package manager" >&2
  exit 1
fi
