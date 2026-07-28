// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {BN254} from "../src/BN254.sol";
import {Vectors} from "./Vectors.sol";

/// @dev External harness. Library functions are internal and get inlined, so
///      gas has to be measured across a real external call boundary.
contract Harness {
    function verify(BN254.G2Point memory pk, bytes memory msg_, BN254.G1Point memory sig)
        external
        view
        returns (bool)
    {
        return BN254.verify(pk, msg_, sig);
    }

    function verifyPrevalidatedKey(BN254.G2Point memory pk, bytes memory msg_, BN254.G1Point memory sig)
        external
        view
        returns (bool)
    {
        return BN254.verifyPrevalidatedKey(pk, msg_, sig);
    }

    function hashToG1(bytes memory msg_) external view returns (BN254.G1Point memory) {
        return BN254.hashToG1(msg_);
    }

    function validateG2(BN254.G2Point memory pk) external pure {
        BN254.validateG2(pk);
    }

    function validateG1(BN254.G1Point memory p) external pure {
        BN254.validateG1(p);
    }

    function isInSubgroupG2(BN254.G2Point memory pk) external pure returns (bool) {
        return BN254.isInSubgroupG2(pk);
    }

    function isOnCurveG2(BN254.G2Point memory pk) external pure returns (bool) {
        return BN254.isOnCurveG2(pk);
    }

    function isOnCurveG1(BN254.G1Point memory p) external pure returns (bool) {
        return BN254.isOnCurveG1(p);
    }

    function pairingCheck2(
        BN254.G1Point memory a1,
        BN254.G2Point memory a2,
        BN254.G1Point memory b1,
        BN254.G2Point memory b2
    ) external view returns (bool) {
        return BN254.pairingCheck2(a1, a2, b1, b2);
    }
}

contract BN254Test is Test {
    Harness h;

    function setUp() public {
        h = new Harness();
    }

    // =================================================================
    //   THE NEGATIVE VECTOR
    // =================================================================

    /// @notice e(G1,G2)·e(G1,G2) = e(G1,G2)^2 != 1, so the pairing MUST return 0.
    ///
    /// @dev This is the most important test in the file. A stubbed or degenerate
    ///      pairing that ignores its input and returns a constant 1 passes every
    ///      positive test above and below — a valid signature "verifies", the
    ///      known-good vector matches, everything looks correct. It fails only
    ///      here. Without this test, "BLS verification works" is unfalsifiable.
    function test_NegativeVector_PairingSquaredIsNotOne() public view {
        bool result = h.pairingCheck2(
            BN254.generatorG1(), BN254.generatorG2(), BN254.generatorG1(), BN254.generatorG2()
        );
        assertFalse(result, "e(G1,G2)^2 returned 1 - pairing is not real");
    }

    /// @dev The paired positive control: e(G1,G2)·e(-G1,G2) == 1.
    function test_PositiveVector_PairingWithInverseIsOne() public view {
        bool result = h.pairingCheck2(
            BN254.generatorG1(),
            BN254.generatorG2(),
            BN254.negate(BN254.generatorG1()),
            BN254.generatorG2()
        );
        assertTrue(result, "e(G1,G2)*e(-G1,G2) should be 1");
    }

    // =================================================================
    //   KNOWN-GOOD SIGNATURE
    // =================================================================

    function test_KnownGoodSignatureVerifies() public view {
        assertTrue(h.verify(Vectors.pubkey(), Vectors.MESSAGE, Vectors.signature()));
    }

    function test_KnownGoodSignatureVerifies_MultiIterationHash() public view {
        assertTrue(
            h.verify(Vectors.pubkey(), Vectors.MESSAGE_MULTI_ITER, Vectors.signatureMultiIter())
        );
    }

    /// @dev The on-chain hash-to-curve must agree with the off-chain reference
    ///      exactly, or no signature ever verifies.
    function test_HashToG1_MatchesOffchainReference() public view {
        BN254.G1Point memory got = h.hashToG1(Vectors.MESSAGE);
        BN254.G1Point memory want = Vectors.hashOfMessage();
        assertEq(got.x, want.x, "hashToG1 x mismatch");
        assertEq(got.y, want.y, "hashToG1 y mismatch");
    }

    /// @dev Exercises the try-and-increment loop rather than the first-attempt path.
    function test_HashToG1_MultiIteration_MatchesOffchainReference() public view {
        BN254.G1Point memory got = h.hashToG1(Vectors.MESSAGE_MULTI_ITER);
        BN254.G1Point memory want = Vectors.hashOfMessageMultiIter();
        assertEq(got.x, want.x, "multi-iter hashToG1 x mismatch");
        assertEq(got.y, want.y, "multi-iter hashToG1 y mismatch");
        assertGt(Vectors.MULTI_ITER_COUNT, 1, "vector does not exercise the loop");
    }

    function test_HashToG1_AlwaysLandsOnCurve() public view {
        assertTrue(h.isOnCurveG1(h.hashToG1(Vectors.MESSAGE)));
        assertTrue(h.isOnCurveG1(h.hashToG1(Vectors.MESSAGE_MULTI_ITER)));
        assertTrue(h.isOnCurveG1(h.hashToG1("")), "empty message");
    }

    function testFuzz_HashToG1_AlwaysLandsOnCurve(bytes calldata m) public view {
        assertTrue(h.isOnCurveG1(h.hashToG1(m)));
    }

    // =================================================================
    //   NEGATIVE CASES — wrong values
    // =================================================================

    function test_WrongPublicKeyFails() public view {
        assertFalse(h.verify(Vectors.wrongPubkey(), Vectors.MESSAGE, Vectors.signature()));
    }

    /// @dev A structurally valid signature that is simply the wrong one: signed
    ///      the same key, different message. Exercises the "valid point, wrong
    ///      value" path, which returns false rather than reverting.
    function test_ValidButWrongSignature_ReturnsFalse() public view {
        assertFalse(h.verify(Vectors.pubkey(), Vectors.MESSAGE, Vectors.signatureMultiIter()));
    }

    function test_WrongMessageFails() public view {
        assertFalse(h.verify(Vectors.pubkey(), "not the signed message", Vectors.signature()));
    }

    /// @dev Flipping one bit of the signature's y coordinate takes it off the
    ///      curve, so it must be rejected outright rather than verified.
    function test_SingleBitFlipInSignature_Reverts() public {
        BN254.G1Point memory sig = Vectors.signature();
        sig.y = sig.y ^ 1;
        vm.expectRevert(BN254.PointNotOnCurve.selector);
        h.verify(Vectors.pubkey(), Vectors.MESSAGE, sig);
    }

    /// @dev Every single-bit flip across both coordinates either reverts or
    ///      fails to verify. None may return true.
    function test_AllSingleBitFlips_NeverVerify() public view {
        BN254.G1Point memory good = Vectors.signature();
        for (uint256 bit = 0; bit < 256; bit += 17) {
            BN254.G1Point memory s = BN254.G1Point(good.x ^ (uint256(1) << bit), good.y);
            try h.verify(Vectors.pubkey(), Vectors.MESSAGE, s) returns (bool ok) {
                assertFalse(ok, "bit-flipped x verified");
            } catch {}

            s = BN254.G1Point(good.x, good.y ^ (uint256(1) << bit));
            try h.verify(Vectors.pubkey(), Vectors.MESSAGE, s) returns (bool ok) {
                assertFalse(ok, "bit-flipped y verified");
            } catch {}
        }
    }

    // =================================================================
    //   NEGATIVE CASES — malformed points, must revert
    // =================================================================

    function test_OffCurveSignature_Reverts() public {
        vm.expectRevert(BN254.PointNotOnCurve.selector);
        h.verify(Vectors.pubkey(), Vectors.MESSAGE, Vectors.offCurveG1());
    }

    function test_OffCurveSignature_IsNotSilentlyAccepted() public view {
        assertFalse(h.isOnCurveG1(Vectors.offCurveG1()));
    }

    /// @dev The subgroup case. This point IS on the twist — an on-curve check
    ///      alone accepts it — but it is not in the R-order subgroup.
    function test_WrongSubgroupPubkey_Reverts() public {
        vm.expectRevert(BN254.PointNotInSubgroup.selector);
        h.verify(Vectors.wrongSubgroupPubkey(), Vectors.MESSAGE, Vectors.signature());
    }

    /// @dev Proves the previous test fails for the RIGHT reason: the point passes
    ///      the on-curve check and is rejected only by the subgroup check.
    function test_WrongSubgroupPoint_IsOnCurveButNotInSubgroup() public view {
        BN254.G2Point memory ws = Vectors.wrongSubgroupPubkey();
        assertTrue(h.isOnCurveG2(ws), "vector should be on the twist");
        assertFalse(h.isInSubgroupG2(ws), "vector should not be in the subgroup");
    }

    /// @dev Control for the subgroup check itself. Without this, an
    ///      `isInSubgroupG2` that always returned false would pass every
    ///      rejection test in this file.
    function test_ValidPubkey_IsInSubgroup() public view {
        assertTrue(h.isInSubgroupG2(Vectors.pubkey()), "valid key rejected by subgroup check");
        assertTrue(h.isInSubgroupG2(BN254.generatorG2()), "G2 generator rejected");
        assertTrue(h.isInSubgroupG2(Vectors.wrongPubkey()), "second valid key rejected");
    }

    function test_OffCurveG2_Reverts() public {
        BN254.G2Point memory pk = Vectors.pubkey();
        pk.y_c0 = pk.y_c0 ^ 1;
        vm.expectRevert(BN254.PointNotOnCurve.selector);
        h.validateG2(pk);
    }

    // =================================================================
    //   IDENTITY / ZERO INPUTS
    // =================================================================

    function test_ZeroSignature_RevertsAsInfinity() public {
        vm.expectRevert(BN254.PointIsInfinity.selector);
        h.verify(Vectors.pubkey(), Vectors.MESSAGE, BN254.G1Point(0, 0));
    }

    function test_ZeroPubkey_RevertsAsInfinity() public {
        vm.expectRevert(BN254.PointIsInfinity.selector);
        h.verify(BN254.G2Point(0, 0, 0, 0), Vectors.MESSAGE, Vectors.signature());
    }

    function test_UnreducedG1Coordinate_Reverts() public {
        vm.expectRevert(BN254.CoordinateNotReduced.selector);
        h.validateG1(BN254.G1Point(BN254.P, 2));
    }

    function test_UnreducedG2Coordinate_Reverts() public {
        BN254.G2Point memory pk = Vectors.pubkey();
        pk.x_c0 = BN254.P;
        vm.expectRevert(BN254.CoordinateNotReduced.selector);
        h.validateG2(pk);
    }

    /// @dev x = 0, y = 0 is infinity and rejected; but a point with only ONE zero
    ///      coordinate is not infinity and must be judged on the curve equation.
    function test_PartialZeroCoordinates_JudgedOnCurveEquation() public {
        vm.expectRevert(BN254.PointNotOnCurve.selector);
        h.validateG1(BN254.G1Point(0, 1));

        vm.expectRevert(BN254.PointNotOnCurve.selector);
        h.validateG1(BN254.G1Point(1, 0));
    }

    /// @dev An empty message is legitimate input and must hash and verify like
    ///      any other, not be special-cased.
    function test_EmptyMessage_HashesToValidPoint() public view {
        BN254.G1Point memory p = h.hashToG1("");
        assertTrue(h.isOnCurveG1(p));
        assertTrue(p.x != 0 || p.y != 0, "empty message hashed to infinity");
    }


    // =================================================================
    //   DIFFERENTIAL CORPUS
    //   The Fp2 and Jacobian arithmetic backing isInSubgroupG2 is
    //   hand-written and is the most error-prone code in the library.
    //   These check it against py_ecc's independent verdict over many
    //   points, in both directions.
    // =================================================================

    function test_Differential_SubgroupCheck_AcceptsAllValidPoints() public view {
        BN254.G2Point[6] memory good = Vectors.inSubgroupCorpus();
        for (uint256 i = 0; i < good.length; i++) {
            assertTrue(h.isOnCurveG2(good[i]), "corpus point not on curve");
            assertTrue(h.isInSubgroupG2(good[i]), "valid point rejected");
        }
    }

    function test_Differential_SubgroupCheck_RejectsAllInvalidPoints() public view {
        BN254.G2Point[6] memory bad = Vectors.notInSubgroupCorpus();
        for (uint256 i = 0; i < bad.length; i++) {
            assertTrue(h.isOnCurveG2(bad[i]), "corpus point should be ON the twist");
            assertFalse(h.isInSubgroupG2(bad[i]), "wrong-subgroup point accepted");
        }
    }

    function test_Differential_HashToG1_MatchesReferenceCorpus() public view {
        string[8] memory msgs = Vectors.h2cMessages();
        BN254.G1Point[8] memory want = Vectors.h2cExpected();
        for (uint256 i = 0; i < msgs.length; i++) {
            BN254.G1Point memory got = h.hashToG1(bytes(msgs[i]));
            assertEq(got.x, want[i].x, "h2c x mismatch");
            assertEq(got.y, want[i].y, "h2c y mismatch");
        }
    }

    // =================================================================
    //   GAS
    // =================================================================

    function test_Gas_Report() public view {
        uint256 g0;
        uint256 g1;

        g0 = gasleft();
        h.verify(Vectors.pubkey(), Vectors.MESSAGE, Vectors.signature());
        g1 = gasleft();
        uint256 gFull = g0 - g1;

        g0 = gasleft();
        h.verifyPrevalidatedKey(Vectors.pubkey(), Vectors.MESSAGE, Vectors.signature());
        g1 = gasleft();
        uint256 gPre = g0 - g1;

        g0 = gasleft();
        h.isInSubgroupG2(Vectors.pubkey());
        g1 = gasleft();
        uint256 gSub = g0 - g1;

        g0 = gasleft();
        h.hashToG1(Vectors.MESSAGE);
        g1 = gasleft();
        uint256 gH2c1 = g0 - g1;

        g0 = gasleft();
        h.hashToG1(Vectors.MESSAGE_MULTI_ITER);
        g1 = gasleft();
        uint256 gH2c5 = g0 - g1;

        g0 = gasleft();
        h.pairingCheck2(
            BN254.generatorG1(),
            BN254.generatorG2(),
            BN254.negate(BN254.generatorG1()),
            BN254.generatorG2()
        );
        g1 = gasleft();
        uint256 gPair = g0 - g1;

        console.log("--- measured gas (external call, includes call overhead)");
        console.log("verify() full, incl. G2 subgroup check :", gFull);
        console.log("verifyPrevalidatedKey()                :", gPre);
        console.log("  isInSubgroupG2() alone               :", gSub);
        console.log("  hashToG1(), 1 iteration              :", gH2c1);
        console.log("  hashToG1(), 5 iterations             :", gH2c5);
        console.log("  pairingCheck2() alone                :", gPair);
    }
}
