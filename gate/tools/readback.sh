#!/usr/bin/env bash
# Read every result back from chain storage. Usage: readback.sh <rpc> <addr> <label>
set -u
RPC="$1"; C="$2"; LABEL="$3"
TWOGX="0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3"
TWOGY="0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4"

q() { cast call "$C" "$1" --rpc-url "$RPC" | tr -d '\n'; }
dec() { cast to-dec "$1" 2>/dev/null || echo "$1"; }

echo "=========== READ BACK FROM CHAIN: $LABEL"
echo "contract: $C"
echo "ran()             = $(cast call "$C" 'ran()(bool)' --rpc-url "$RPC")"
echo
echo "--- 0x06 ecadd   G1 + G1 == 2*G1"
echo "  success   = $(cast call "$C" 'ecAddOk()(bool)' --rpc-url "$RPC")"
echo "  gas       = $(cast call "$C" 'ecAddGas()(uint256)' --rpc-url "$RPC")"
AX=$(q 'ecAddX()(uint256)'); AY=$(q 'ecAddY()(uint256)')
AXH=$(cast to-uint256 "$(echo $AX | awk '{print $1}')" 2>/dev/null)
AYH=$(cast to-uint256 "$(echo $AY | awk '{print $1}')" 2>/dev/null)
echo "  returned x= $AXH"
echo "  expected x= $TWOGX"
echo "  returned y= $AYH"
echo "  expected y= $TWOGY"
[ "$AXH" = "$TWOGX" ] && [ "$AYH" = "$TWOGY" ] && echo "  VERDICT   = CORRECT" || echo "  VERDICT   = WRONG"
echo
echo "--- 0x07 ecmul   G1 * 2 == 2*G1"
echo "  success   = $(cast call "$C" 'ecMulOk()(bool)' --rpc-url "$RPC")"
echo "  gas       = $(cast call "$C" 'ecMulGas()(uint256)' --rpc-url "$RPC")"
MX=$(q 'ecMulX()(uint256)'); MY=$(q 'ecMulY()(uint256)')
MXH=$(cast to-uint256 "$(echo $MX | awk '{print $1}')" 2>/dev/null)
MYH=$(cast to-uint256 "$(echo $MY | awk '{print $1}')" 2>/dev/null)
echo "  returned x= $MXH"
echo "  expected x= $TWOGX"
echo "  returned y= $MYH"
echo "  expected y= $TWOGY"
[ "$MXH" = "$TWOGX" ] && [ "$MYH" = "$TWOGY" ] && echo "  VERDICT   = CORRECT" || echo "  VERDICT   = WRONG"
echo
echo "--- 0x08 ecpairing  2 pairs, product == 1  (expect 1)"
echo "  success   = $(cast call "$C" 'pairTrueOk()(bool)' --rpc-url "$RPC")"
echo "  gas       = $(cast call "$C" 'pairTrueGas()(uint256)' --rpc-url "$RPC")"
PT=$(cast call "$C" 'pairTrueOut()(uint256)' --rpc-url "$RPC" | awk '{print $1}')
echo "  returned  = $PT   expected = 1"
echo
echo "--- 0x08 ecpairing  2 pairs, product != 1  (expect 0)  << anti-stub control"
echo "  success   = $(cast call "$C" 'pairFalseOk()(bool)' --rpc-url "$RPC")"
echo "  gas       = $(cast call "$C" 'pairFalseGas()(uint256)' --rpc-url "$RPC")"
PF=$(cast call "$C" 'pairFalseOut()(uint256)' --rpc-url "$RPC" | awk '{print $1}')
echo "  returned  = $PF   expected = 0"
echo
echo "--- 0x08 ecpairing  4 pairs, product == 1  (expect 1)"
echo "  success   = $(cast call "$C" 'pair4Ok()(bool)' --rpc-url "$RPC")"
echo "  gas       = $(cast call "$C" 'pair4Gas()(uint256)' --rpc-url "$RPC")"
P4=$(cast call "$C" 'pair4Out()(uint256)' --rpc-url "$RPC" | awk '{print $1}')
echo "  returned  = $P4   expected = 1"
echo
G2P=$(cast call "$C" 'pairTrueGas()(uint256)' --rpc-url "$RPC" | awk '{print $1}')
G4P=$(cast call "$C" 'pair4Gas()(uint256)' --rpc-url "$RPC" | awk '{print $1}')
echo "  marginal gas per additional pairing = ($G4P - $G2P)/2 = $(( (G4P - G2P) / 2 ))"
echo "  implied fixed base                  = $G2P - 2*$(( (G4P - G2P) / 2 )) = $(( G2P - 2 * ((G4P - G2P)/2) ))"
echo
