// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// EIP-2537 (BLS12-381) precompile-ok vékony burkolója.
/// Kódolás: G1 pont 128 bájt (x, y; mindkettő 64 bájt, a felső 16 bájt nulla),
/// G2 pont 256 bájt (x.c0, x.c1, y.c0, y.c1), a végtelen távoli pont csupa nulla.
library BLS {
    address internal constant G1_ADD = address(0x0b);
    address internal constant G1_MSM = address(0x0c);
    address internal constant G2_ADD = address(0x0d);
    address internal constant G2_MSM = address(0x0e);
    address internal constant PAIRING = address(0x0f);
    address internal constant MODEXP = address(0x05);

    uint256 internal constant G1_LEN = 128;
    uint256 internal constant G2_LEN = 256;

    /// a skalártest rendje (r)
    uint256 internal constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // az alaptest modulusa (p), 64 bájtos kódolásban két szóra bontva
    uint256 private constant P_HI = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 private constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    error PrecompileFailed(address precompile);
    error BadG1Length(uint256 length);
    error BadG2Length(uint256 length);

    function g1() internal pure returns (bytes memory) {
        return hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
            hex"0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    }

    function g2() internal pure returns (bytes memory) {
        return hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
            hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
            hex"000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
            hex"000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
    }

    function checkG1(bytes memory p) internal pure {
        if (p.length != G1_LEN) revert BadG1Length(p.length);
    }

    function checkG2(bytes memory p) internal pure {
        if (p.length != G2_LEN) revert BadG2Length(p.length);
    }

    function isZero(bytes memory p) internal pure returns (bool) {
        for (uint256 i = 0; i < p.length; i += 32) {
            bytes32 w;
            assembly { w := mload(add(add(p, 32), i)) }
            if (w != bytes32(0)) return false;
        }
        return true;
    }

    function _call(address pre, bytes memory input) private view returns (bytes memory out) {
        bool ok;
        (ok, out) = pre.staticcall(input);
        if (!ok) revert PrecompileFailed(pre);
    }

    function g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        return _call(G1_ADD, abi.encodePacked(a, b));
    }

    function g2Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        return _call(G2_ADD, abi.encodePacked(a, b));
    }

    /// p^s G1-ben; az MSM a részcsoport-tagságot is ellenőrzi
    function g1Mul(bytes memory p, uint256 s) internal view returns (bytes memory) {
        return _call(G1_MSM, abi.encodePacked(p, s));
    }

    function g2Mul(bytes memory p, uint256 s) internal view returns (bytes memory) {
        return _call(G2_MSM, abi.encodePacked(p, s));
    }

    function g1Msm(bytes[] memory ps, uint256[] memory ss) internal view returns (bytes memory) {
        bytes memory input;
        for (uint256 i = 0; i < ps.length; i++) {
            input = abi.encodePacked(input, ps[i], ss[i]);
        }
        return _call(G1_MSM, input);
    }

    function g2Msm(bytes[] memory ps, uint256[] memory ss) internal view returns (bytes memory) {
        bytes memory input;
        for (uint256 i = 0; i < ps.length; i++) {
            input = abi.encodePacked(input, ps[i], ss[i]);
        }
        return _call(G2_MSM, input);
    }

    /// -p G1-ben: y helyett p - y (két 256 bites szóban, átvitellel)
    function g1Neg(bytes memory p) internal pure returns (bytes memory out) {
        checkG1(p);
        if (isZero(p)) return p;
        uint256 yHi;
        uint256 yLo;
        assembly {
            yHi := mload(add(p, 96))
            yLo := mload(add(p, 128))
        }
        uint256 lo;
        uint256 borrow;
        unchecked {
            lo = P_LO - yLo;
            borrow = P_LO < yLo ? 1 : 0;
        }
        uint256 hi = P_HI - yHi - borrow;
        out = new bytes(G1_LEN);
        assembly {
            mstore(add(out, 32), mload(add(p, 32)))
            mstore(add(out, 64), mload(add(p, 64)))
            mstore(add(out, 96), hi)
            mstore(add(out, 128), lo)
        }
    }

    /// e(a1, b1) · e(a2, b2) == 1
    function pairing2(bytes memory a1, bytes memory b1, bytes memory a2, bytes memory b2) internal view returns (bool) {
        bytes memory out = _call(PAIRING, abi.encodePacked(a1, b1, a2, b2));
        return out.length == 32 && uint256(bytes32(out)) == 1;
    }

    /// e(a1, b1) · e(a2, b2) · e(a3, b3) == 1
    function pairing3(
        bytes memory a1,
        bytes memory b1,
        bytes memory a2,
        bytes memory b2,
        bytes memory a3,
        bytes memory b3
    ) internal view returns (bool) {
        bytes memory out = _call(PAIRING, abi.encodePacked(a1, b1, a2, b2, a3, b3));
        return out.length == 32 && uint256(bytes32(out)) == 1;
    }

    /// e(x, y) == e(z, w), azaz e(x, y) · e(-z, w) == 1
    function pairingEq(bytes memory x, bytes memory y, bytes memory z, bytes memory w) internal view returns (bool) {
        return pairing2(x, y, g1Neg(z), w);
    }

    /// a^-1 mod r (Fermat, modexp precompile-lal)
    function frInv(uint256 a) internal view returns (uint256) {
        bytes memory out = _call(MODEXP, abi.encodePacked(uint256(32), uint256(32), uint256(32), a % R, R - 2, R));
        return uint256(bytes32(out));
    }

    /// P_S(x) = ∏ (x + s) együtthatói mod r, a konstans tagtól a főegyütthatóig
    function setPolyCoeffs(bytes32[] memory members) internal pure returns (uint256[] memory c) {
        uint256 n = members.length;
        c = new uint256[](n + 1);
        c[0] = 1;
        for (uint256 i = 0; i < n; i++) {
            uint256 s = uint256(members[i]) % R;
            // (c_0 + c_1 x + ... ) · (x + s)
            for (uint256 j = i + 1; j > 0; j--) {
                c[j] = addmod(c[j - 1], mulmod(c[j], s, R), R);
            }
            c[0] = mulmod(c[0], s, R);
        }
    }
}
