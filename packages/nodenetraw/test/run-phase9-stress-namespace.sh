#!/bin/sh
set -eu

exec sh "$(dirname "$0")/run-privileged.sh" namespace ring-stress
