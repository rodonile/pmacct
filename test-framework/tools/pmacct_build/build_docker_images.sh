#!/bin/bash
# Temporary solution until we integrate the framework in the pmacct repo
# Rootless containers --> discuss with Paolo

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

PMACCT_LOCATION="$SCRIPT_DIR/pmacct"
if [ ! -d "$PMACCT_LOCATION" ]; then
  echo "Error: $PMACCT_LOCATION does not exist."
  echo
  echo "     !!! Please clone the pmacct repo in $SCRIPT_DIR !!!"
  echo
  exit 1
fi

TAG='_build'

echo "Building pmacct docker images"
docker build -t pmacct-base:$TAG -f $SCRIPT_DIR/base/Dockerfile $SCRIPT_DIR/pmacct || exit $?

docker build -t nfacctd:$TAG -f $SCRIPT_DIR/nfacctd/Dockerfile_non_root $SCRIPT_DIR/pmacct || exit $?
docker build -t pmbmpd:$TAG -f $SCRIPT_DIR/pmbmpd/Dockerfile_non_root $SCRIPT_DIR/pmacct || exit $?
docker build -t pmbgpd:$TAG -f $SCRIPT_DIR/pmbgpd/Dockerfile_non_root $SCRIPT_DIR/pmacct || exit $?
