#!/usr/bin/env bash
# Read-only precompile probe: raw eth_call against a given RPC.
# Usage: probe.sh <rpc-url> <label>
set -u
RPC="$1"; LABEL="$2"
SP="$(dirname "$0")"
VEC="$SP/vectors.json"

python3 "$SP/vectors.py" > "$VEC"

echo "=================== $LABEL  ($RPC)"
for name in ecadd ecmul pair_true pair_false; do
  addr=$(python3 -c "import json;print(json.load(open('$VEC'))['$name']['addr'])")
  data=$(python3 -c "import json;print(json.load(open('$VEC'))['$name']['input'])")
  want=$(python3 -c "import json;print(json.load(open('$VEC'))['$name']['expect'])")

  got=$(cast rpc eth_call "{\"to\":\"$addr\",\"data\":\"$data\"}" "latest" --rpc-url "$RPC" 2>&1 | tr -d '"')
  gas=$(cast rpc eth_estimateGas "{\"to\":\"$addr\",\"data\":\"$data\"}" --rpc-url "$RPC" 2>&1 | tr -d '"')

  if [ "$got" = "$want" ]; then verdict="CORRECT"; else verdict="MISMATCH"; fi
  echo "--- $name @ $addr"
  echo "    want: $want"
  echo "    got : $got"
  echo "    -> $verdict   (eth_estimateGas incl. 21000 intrinsic: $gas)"
done
echo
