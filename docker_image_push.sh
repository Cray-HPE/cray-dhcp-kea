#!/usr/bin/env bash
IMAGE_NAME="cray-dhcp-kea"
usage() {
    echo "$FUNCNAME: $0"
    echo "  -h | prints this help message"
    echo "  -l | hostname to push to, default localhost";
    echo "  -r | repo to push to, default cray";
    echo "  -t | tag to use for image, default to latest";
    echo "  -f | forces build with --no-cache and --pull";
	echo "";
    exit 0
}
REPO="cray"
TAG="latest"
REGISTRY_HOSTNAME="localhost"
FORCE=" "
while getopts "hfl:r:t:" opt; do
  case ${opt} in
    h)
      usage;
      exit;;
    f)
      FORCE=" --no-cache --pull";;
    l)
      REGISTRY_HOSTNAME=${OPTARG};;
    r)
      REPO=${OPTARG};;
    t)
      TAG=${OPTARG};;
    *)
      usage;
      exit;;
  esac
done
shift $((OPTIND-1))
echo "Building $FORCE and pushing $IMAGE_NAME:$TAG to $REGISTRY_HOSTNAME in repo $REPO"
set -ex
docker build ${FORCE} -t cray/${IMAGE_NAME}:${TAG} -f Dockerfile.dhcp-kea .
docker tag cray/${IMAGE_NAME}:${TAG} ${REGISTRY_HOSTNAME}/${REPO}/${IMAGE_NAME}:${TAG}
docker push ${REGISTRY_HOSTNAME}/${REPO}/${IMAGE_NAME}:${TAG}
