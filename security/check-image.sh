#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
image=${1:?Usage: check-image.sh IMAGE}
# Test the immutable local image ID; never execute its application entrypoint.
image_id=$(docker image inspect --format '{{.Id}}' "$image")
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 512m \
  --mount "type=bind,src=$root,dst=/runtime-security,readonly" \
  --entrypoint /bin/sh "$image_id" /runtime-security/check-runtime.sh
test "$(docker image inspect --format '{{.Id}}' "$image")" = "$image_id"
echo "Verified image: $image_id"
