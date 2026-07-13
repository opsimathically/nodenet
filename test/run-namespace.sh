#!/bin/sh
set -eu

if [ "${NODENETRAW_IN_NAMESPACE:-0}" = "1" ]; then
  ip link set lo up
  ip link add nr-veth0 type veth peer name nr-veth1
  ip link set dev nr-veth0 address 02:00:00:00:00:01
  ip link set dev nr-veth1 address 02:00:00:00:00:02
  ip link set nr-veth0 up
  ip link set nr-veth1 up
  node=${NODENETRAW_NODE:-$(command -v node)}
  case "${NODENETRAW_TEST_SUITE:-privileged}" in
    privileged)
      exec env NODENETRAW_PRIVILEGED_TESTS=1 "$node" --test test/privileged.test.mjs
      ;;
    event-stress)
      exec "$node" test/phase11-event-stress.mjs
      ;;
    *)
      echo "unknown privileged test suite: ${NODENETRAW_TEST_SUITE:-}" >&2
      exit 2
      ;;
  esac
fi

if [ "$(id -u)" -eq 0 ]; then
  exec unshare --net env NODENETRAW_IN_NAMESPACE=1 sh "$0"
fi

exec unshare --user --map-root-user --net \
  env NODENETRAW_IN_NAMESPACE=1 sh "$0"
