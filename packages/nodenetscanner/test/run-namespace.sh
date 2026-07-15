#!/bin/sh
set -eu

package_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
repository_root=$(CDPATH= cd -- "$package_root/../.." && pwd)
script_path="$package_root/test/run-namespace.sh"
cd "$repository_root"

is_supported_node() {
  [ -x "$1" ] || return 1
  major=$("$1" -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null) || return 1
  [ "$major" -ge 26 ]
}

find_node() {
  home=$1
  if [ -n "${NODENETSCANNER_NODE:-}" ] && is_supported_node "$NODENETSCANNER_NODE"; then
    printf '%s\n' "$NODENETSCANNER_NODE"
    return
  fi
  requested=$(sed -n '1p' "$repository_root/.nvmrc" 2>/dev/null || true)
  if [ -n "$requested" ] && [ -d "$home/.nvm/versions/node" ]; then
    candidate=$(find "$home/.nvm/versions/node" -path "*/v${requested}*/bin/node" -type f 2>/dev/null | sort -V | tail -n 1)
    if [ -n "$candidate" ] && is_supported_node "$candidate"; then
      printf '%s\n' "$candidate"
      return
    fi
  fi
  for candidate in "$home/.volta/bin/node" "$home/.local/share/mise/shims/node" /usr/local/bin/node /usr/bin/node; do
    if is_supported_node "$candidate"; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  echo "could not find Node.js 26+; set NODENETSCANNER_NODE to its absolute path" >&2
  exit 1
}

build_as_owner() {
  owner=$1
  home=$2
  node=$3
  workspace=$4
  node_bin=$(dirname "$node")
  runner=$(command -v runuser || true)
  if [ -z "$runner" ] || [ ! -x "$node_bin/npm" ]; then
    echo "runuser and npm beside $node are required to build as $owner" >&2
    exit 1
  fi
  "$runner" -u "$owner" -- env \
    HOME="$home" USER="$owner" LOGNAME="$owner" \
    CARGO_HOME="$home/.cargo" RUSTUP_HOME="$home/.rustup" \
    PATH="$node_bin:$home/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    "$node_bin/npm" run build --workspace="$workspace"
}

build_phase25_lab_as_owner() {
  owner=$1
  home=$2
  node=$3
  runner=$(command -v runuser || true)
  if [ -z "$runner" ]; then
    echo "runuser is required to build the Phase 25 lab as $owner" >&2
    exit 1
  fi
  "$runner" -u "$owner" -- env \
    HOME="$home" USER="$owner" LOGNAME="$owner" \
    CARGO_HOME="$home/.cargo" RUSTUP_HOME="$home/.rustup" \
    PATH="$(dirname "$node"):$home/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    cargo build -p nodenetscanner-native --example phase25_backend_lab --locked
}

if [ "${NODENETSCANNER_IN_NAMESPACE:-0}" = "1" ]; then
  ip link set lo up
  unshare --net sh -c 'ip link set lo up; exec sleep 300' &
  target_pid=$!
  target_server=
  ready_file=
  cleanup() {
    [ -z "$target_server" ] || kill "$target_server" 2>/dev/null || true
    kill "$target_pid" 2>/dev/null || true
    wait "$target_pid" 2>/dev/null || true
    [ -z "$ready_file" ] || rm -f "$ready_file"
  }
  trap cleanup EXIT INT TERM

  ip link add scan0 address 02:00:00:00:22:01 type veth peer name target0 address 02:00:00:00:22:02
  ip link set target0 netns "$target_pid"
  ip address add 192.0.2.1/24 dev scan0
  ip -6 address add 2001:db8:22::1/64 dev scan0 nodad
  ip address add 198.51.100.1/24 dev scan0
  ip link set scan0 up
  if [ "${NODENETSCANNER_PHASE25_BENCHMARK:-0}" = "1" ]; then
    ip link add bench0 type veth peer name bench1
    ip link set dev bench0 address 02:00:00:00:25:01
    ip link set dev bench1 address 02:00:00:00:25:02
    ip link set bench0 up
    ip link set bench1 up
    ip link add txlab0 type veth peer name txlab1
    ip link set dev txlab0 address 02:00:00:00:25:11
    ip link set dev txlab1 address 02:00:00:00:25:12
    ip link set txlab0 up
    ip link set txlab1 up
  fi
  stable=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! ip -6 address show dev scan0 tentative | grep -q tentative; then
      stable=1
      break
    fi
    sleep 1
  done
  if [ "$stable" -ne 1 ]; then
    echo "scan0 IPv6 addresses did not leave tentative state" >&2
    exit 1
  fi

  nsenter -t "$target_pid" -n ip address add 192.0.2.2/24 dev target0
  nsenter -t "$target_pid" -n ip -6 address add 2001:db8:22::2/64 dev target0 nodad
  nsenter -t "$target_pid" -n ip link set target0 up
  nsenter -t "$target_pid" -n ip link add link target0 name target0.42 type vlan id 42
  nsenter -t "$target_pid" -n ip address add 198.51.100.2/24 dev target0.42
  nsenter -t "$target_pid" -n ip link set target0.42 up

  ready_file=$(mktemp)
  nsenter -t "$target_pid" -n "$NODENETSCANNER_NODE" \
    packages/nodenetscanner/test/fixtures/namespace-target.mjs >"$ready_file" 2>&1 &
  target_server=$!
  ready=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if grep -q '^READY$' "$ready_file"; then
      ready=1
      break
    fi
    if ! kill -0 "$target_server" 2>/dev/null; then
      cat "$ready_file" >&2
      exit 1
    fi
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then
    cat "$ready_file" >&2
    echo "namespace target did not become ready" >&2
    exit 1
  fi
  if [ "${NODENETSCANNER_NAMESPACE_DEBUG:-0}" = "1" ]; then
    ip -details link show >&2
    ip address show >&2
    ip route show table all >&2
    ip -6 route show table all >&2
  fi
  if [ "${NODENETSCANNER_PHASE25_BENCHMARK:-0}" = "1" ]; then
    env \
      NODENETSCANNER_PHASE25_HOST_INVENTORY="${NODENETSCANNER_PHASE25_HOST_INVENTORY:-}" \
      NODENETSCANNER_PHASE25_OUTPUT="${NODENETSCANNER_PHASE25_OUTPUT:-}" \
      NODENETSCANNER_PHASE25_RING_ONLY="${NODENETSCANNER_PHASE25_RING_ONLY:-0}" \
      NODENETSCANNER_PHASE25_TRACE="${NODENETSCANNER_PHASE25_TRACE:-0}" \
      "$NODENETSCANNER_NODE" packages/nodenetscanner/test/phase25-benchmark.mjs
  elif [ "${NODENETSCANNER_BENCHMARK:-0}" = "1" ]; then
    env NODENETSCANNER_PRIVILEGED_TESTS=1 \
      "$NODENETSCANNER_NODE" packages/nodenetscanner/test/benchmark.mjs
  elif [ "${NODENETSCANNER_PHASE24_TESTS:-0}" = "1" ]; then
    env \
      NODENETSCANNER_PRIVILEGED_TESTS=1 \
      NODENETSCANNER_NAMESPACE_MATRIX=1 \
      "$NODENETSCANNER_NODE" --test packages/nodenetscanner/test/privileged.test.mjs
    env \
      NODENETSCANNER_PHASE24_TESTS=1 \
      "$NODENETSCANNER_NODE" --test packages/nodenetscanner/test/phase24-privileged.test.mjs
  else
    env \
      NODENETSCANNER_PRIVILEGED_TESTS=1 \
      NODENETSCANNER_NAMESPACE_MATRIX=1 \
      "$NODENETSCANNER_NODE" --test packages/nodenetscanner/test/privileged.test.mjs
  fi
  exit 0
fi

if [ "$(id -u)" -eq 0 ]; then
  owner=${SUDO_USER:-$(stat -c %U "$repository_root")}
  if [ "$owner" != root ]; then
    owner_home=$(getent passwd "$owner" | cut -d: -f6)
    node=$(find_node "$owner_home")
    build_as_owner "$owner" "$owner_home" "$node" @opsimathically/nodenetscanner
    if [ "${NODENETSCANNER_PHASE25_BENCHMARK:-0}" = "1" ]; then
      build_as_owner "$owner" "$owner_home" "$node" @opsimathically/nodenetraw
      build_phase25_lab_as_owner "$owner" "$owner_home" "$node"
    fi
  else
    node=$(find_node "${HOME:-/root}")
    npm run build --workspace=@opsimathically/nodenetscanner
    if [ "${NODENETSCANNER_PHASE25_BENCHMARK:-0}" = "1" ]; then
      npm run build --workspace=@opsimathically/nodenetraw
      cargo build -p nodenetscanner-native --example phase25_backend_lab --locked
    fi
  fi
  host_inventory=
  if [ "${NODENETSCANNER_PHASE25_BENCHMARK:-0}" = "1" ]; then
    host_inventory=$("$node" packages/nodenetscanner/test/phase25-benchmark.mjs --inventory | base64 -w 0)
  fi
  exec unshare --net env \
    NODENETSCANNER_IN_NAMESPACE=1 \
    NODENETSCANNER_PHASE24_TESTS="${NODENETSCANNER_PHASE24_TESTS:-0}" \
    NODENETSCANNER_BENCHMARK="${NODENETSCANNER_BENCHMARK:-0}" \
    NODENETSCANNER_PHASE25_BENCHMARK="${NODENETSCANNER_PHASE25_BENCHMARK:-0}" \
    NODENETSCANNER_PHASE25_HOST_INVENTORY="$host_inventory" \
    NODENETSCANNER_PHASE25_TRACE="${NODENETSCANNER_PHASE25_TRACE:-0}" \
    NODENETSCANNER_PHASE25_OUTPUT="${NODENETSCANNER_PHASE25_OUTPUT:-}" \
    NODENETSCANNER_PHASE25_RING_ONLY="${NODENETSCANNER_PHASE25_RING_ONLY:-0}" \
    NODENETSCANNER_NODE="$node" \
    PATH="$(dirname "$node"):/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    sh "$script_path"
fi

node=$(command -v node)
if ! is_supported_node "$node"; then
  echo "test:namespace requires Node.js 26+" >&2
  exit 1
fi
npm run build --workspace=@opsimathically/nodenetscanner
if [ "${NODENETSCANNER_PHASE25_BENCHMARK:-0}" = "1" ]; then
  npm run build --workspace=@opsimathically/nodenetraw
  cargo build -p nodenetscanner-native --example phase25_backend_lab --locked
  host_inventory=$("$node" packages/nodenetscanner/test/phase25-benchmark.mjs --inventory | base64 -w 0)
else
  host_inventory=
fi
exec unshare --user --map-root-user --net env \
  NODENETSCANNER_IN_NAMESPACE=1 \
  NODENETSCANNER_NODE="$node" \
  NODENETSCANNER_PHASE24_TESTS="${NODENETSCANNER_PHASE24_TESTS:-0}" \
  NODENETSCANNER_BENCHMARK="${NODENETSCANNER_BENCHMARK:-0}" \
  NODENETSCANNER_PHASE25_BENCHMARK="${NODENETSCANNER_PHASE25_BENCHMARK:-0}" \
  NODENETSCANNER_PHASE25_HOST_INVENTORY="$host_inventory" \
  NODENETSCANNER_PHASE25_TRACE="${NODENETSCANNER_PHASE25_TRACE:-0}" \
  NODENETSCANNER_PHASE25_OUTPUT="${NODENETSCANNER_PHASE25_OUTPUT:-}" \
  NODENETSCANNER_PHASE25_RING_ONLY="${NODENETSCANNER_PHASE25_RING_ONLY:-0}" \
  sh "$script_path"
