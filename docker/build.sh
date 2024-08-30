#!/bin/bash
if [[ "$BUILD_TAG" == "" ]]; then
	echo "usage: BUILD_TAG is empty"
	exit 1
fi
cd $(dirname $0)/..
docker buildx build \
	-f docker/Dockerfile \
	-t notaryserverbuilds.azurecr.io/dev/sgx-${BUILD_TAG} \
	--load . \
	--build-arg BUILD_TAG=${BUILD_TAG}
