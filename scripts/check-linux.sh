#!/usr/bin/env bash

set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
	echo "docker not found; install Docker Desktop or another Docker runtime to use check-linux"
	exit 1
fi

IMAGE="${LINUX_GO_IMAGE:-golang:1.23-bookworm}"

echo "Using Linux check image: ${IMAGE}"

docker run --rm -t \
	-v "$(pwd):/src" \
	-w /src \
	"${IMAGE}" \
	bash -lc '
set -euo pipefail
export PATH="/usr/local/go/bin:${PATH}"
command -v go >/dev/null 2>&1 || {
	echo "go not found in container PATH; set LINUX_GO_IMAGE to a Go toolchain image, for example golang:1.23-bookworm"
	exit 1
}
go version
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends make gcc pkg-config softhsm2 libnss3-tools ca-certificates
GOCACHE=/tmp/gocache make check
'
