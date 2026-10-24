#!/usr/bin/env sh
cd "$(dirname "$0")" || exit 1
if [ -x ./FWArmy ]; then
  ./FWArmy stop "$@"
else
  node ctl.mjs stop "$@"
fi
