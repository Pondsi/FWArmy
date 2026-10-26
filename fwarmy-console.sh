#!/usr/bin/env sh
cd "$(dirname "$0")" || exit 1
if [ -x ./FWArmy ]; then
  exec ./FWArmy console --watch
else
  exec node ctl.mjs console --watch
fi
