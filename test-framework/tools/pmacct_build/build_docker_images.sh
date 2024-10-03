#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
PMACCT_ROOT_LOCATION="$SCRIPT_DIR/../../../"

TAG='_build'

# TODO add script parameter to build with pmacct-gauze too
if "$PMACCT_ROOT_LOCATION/config.status" --config | grep -q "enable-pmacct-gauze"; then

  echo "Building pmacct docker images with pmacct-gauze"
  PMACCT_GAUZE_ROOT_LOCATION=$(realpath "$PMACCT_ROOT_LOCATION/docker")
  if [ ! -d "$PMACCT_GAUZE_ROOT_LOCATION/pmacct-gauze" ]; then
    echo "Error: $PMACCT_GAUZE_ROOT_LOCATION/pmacct-gauze does not exist."
    echo
    echo "     !!! Please clone the pmacct repo in $PMACCT_GAUZE_ROOT_LOCATION !!!"
    echo
    exit 1
  fi

  docker build --build-arg NUM_WORKERS="$(nproc)" -t base:$TAG -f "$PMACCT_ROOT_LOCATION/docker/pmacct-gauze-base/Dockerfile" "$PMACCT_ROOT_LOCATION" || exit $?
else

  echo "Building pmacct docker images"
  docker build --build-arg NUM_WORKERS="$(nproc)" -t base:$TAG -f "$PMACCT_ROOT_LOCATION/docker/base/Dockerfile" "$PMACCT_ROOT_LOCATION" || exit $?
fi

docker build --build-arg NUM_WORKERS="$(nproc)" -t nfacctd:$TAG -f "$PMACCT_ROOT_LOCATION/docker/nfacctd/Dockerfile" "$PMACCT_ROOT_LOCATION" || exit $?
docker build --build-arg NUM_WORKERS="$(nproc)" -t pmacctd:$TAG -f "$PMACCT_ROOT_LOCATION/docker/pmacctd/Dockerfile" "$PMACCT_ROOT_LOCATION" || exit $?
docker build --build-arg NUM_WORKERS="$(nproc)" -t pmbgpd:$TAG -f "$PMACCT_ROOT_LOCATION/docker/pmbgpd/Dockerfile" "$PMACCT_ROOT_LOCATION" || exit $?
docker build --build-arg NUM_WORKERS="$(nproc)" -t pmbmpd:$TAG -f "$PMACCT_ROOT_LOCATION/docker/pmbmpd/Dockerfile" "$PMACCT_ROOT_LOCATION" || exit $?
docker build --build-arg NUM_WORKERS="$(nproc)" -t pmtelemetryd:$TAG -f "$PMACCT_ROOT_LOCATION/docker/pmtelemetryd/Dockerfile" "$PMACCT_ROOT_LOCATION" || exit $?
docker build --build-arg NUM_WORKERS="$(nproc)" -t sfacctd:$TAG -f "$PMACCT_ROOT_LOCATION/docker/sfacctd/Dockerfile" "$PMACCT_ROOT_LOCATION" || exit $?
docker build --build-arg NUM_WORKERS="$(nproc)" -t uacctd:$TAG -f "$PMACCT_ROOT_LOCATION/docker/uacctd/Dockerfile" "$PMACCT_ROOT_LOCATION" || exit $?
