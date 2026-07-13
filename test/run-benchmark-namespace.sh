#!/bin/sh
set -eu

exec unshare --user --map-root-user --net sh -c '
  set -eu
  ip link set lo up
  exec node test/benchmark.mjs
'
