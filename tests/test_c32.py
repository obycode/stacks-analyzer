import unittest

from stacks_analyzer.c32 import c32_address, hash160, pubkey_to_address

# Verbatim from stacks-common/src/address/c32.rs::test_addresses, so the Python
# encoder is pinned to the Rust implementation rather than to itself.
HEX_STRS = [
    "a46ff88886c2ef9762d970b4d2c63678835bd39d",
    "0000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000001",
    "1000000000000000000000000000000000000001",
    "1000000000000000000000000000000000000000",
]
VERSIONS = [22, 0, 31, 20, 26, 21]
C32_ADDRS = [
    [
        "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7",
        "SP000000000000000000002Q6VF78",
        "SP00000000000000000005JA84HQ",
        "SP80000000000000000000000000000004R0CMNV",
        "SP800000000000000000000000000000033H8YKK",
    ],
    [
        "S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE",
        "S0000000000000000000002AA028H",
        "S000000000000000000006EKBDDS",
        "S080000000000000000000000000000007R1QC00",
        "S080000000000000000000000000000003ENTGCQ",
    ],
    [
        "SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR",
        "SZ000000000000000000002ZE1VMN",
        "SZ00000000000000000005HZ3DVN",
        "SZ80000000000000000000000000000004XBV6MS",
        "SZ800000000000000000000000000000007VF5G0",
    ],
    [
        "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G",
        "SM0000000000000000000062QV6X",
        "SM00000000000000000005VR75B2",
        "SM80000000000000000000000000000004WBEWKC",
        "SM80000000000000000000000000000000JGSYGV",
    ],
    [
        "ST2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQYAC0RQ",
        "ST000000000000000000002AMW42H",
        "ST000000000000000000042DB08Y",
        "ST80000000000000000000000000000006BYJ4R4",
        "ST80000000000000000000000000000002YBNPV3",
    ],
    [
        "SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9",
        "SN000000000000000000003YDHWKJ",
        "SN00000000000000000005341MC8",
        "SN800000000000000000000000000000066KZWY0",
        "SN800000000000000000000000000000006H75AK",
    ],
]


class TestC32(unittest.TestCase):
    def test_matches_rust_reference_vectors(self) -> None:
        for version_index, version in enumerate(VERSIONS):
            for hex_index, hex_str in enumerate(HEX_STRS):
                self.assertEqual(
                    c32_address(version, bytes.fromhex(hex_str)),
                    C32_ADDRS[version_index][hex_index],
                    "version=%d hash160=%s" % (version, hex_str),
                )

    def test_leading_zero_bytes_are_preserved(self) -> None:
        """The big-int conversion drops leading zeros; they carry address bits."""
        self.assertEqual(
            c32_address(22, bytes.fromhex("00" * 20)), "SP000000000000000000002Q6VF78"
        )

    def test_hash160_is_ripemd160_of_sha256(self) -> None:
        import hashlib

        data = b"stacks"
        expected = hashlib.new(
            "ripemd160", hashlib.sha256(data).digest()
        ).digest()
        self.assertEqual(hash160(data), expected)

    def test_derives_mainnet_singlesig_addresses_from_pubkeys(self) -> None:
        pubkey = "0284480712192188a0f0b1d0e0e6e3f0c9a6e0f0b9d0a0e0c0b0a0908070605040"
        address = pubkey_to_address(pubkey)
        self.assertTrue(address.startswith("SP"), address)
        # Derivation must be the documented composition, not an independent path.
        self.assertEqual(address, c32_address(22, hash160(bytes.fromhex(pubkey))))

    def test_testnet_flag_changes_version(self) -> None:
        pubkey = "02" + "11" * 32
        self.assertTrue(pubkey_to_address(pubkey, mainnet=True).startswith("SP"))
        self.assertTrue(pubkey_to_address(pubkey, mainnet=False).startswith("ST"))

    def test_bad_input_returns_none_rather_than_raising(self) -> None:
        for bad in ("", None, "zzzz", "02" * 3, "0" * 200):
            self.assertIsNone(pubkey_to_address(bad))

    def test_real_signer_pubkeys_map_one_to_one(self) -> None:
        """Distinct signers must not collide onto one address."""
        pubkeys = [
            "0284480712192188d5ac0e1e01d5e59e05a1b7b8e5c7cbbd8c8e1d1e9f0a0b0c0d",
            "0268e6f499fca2912488e89fc8b6734cafbe24a4ecbcd3312e4eb27ed8e5cfb4f3",
            "02877ce29ba35458b827a6ea18510b9058ae4c30e2c33d288f2982c13497caec6e",
            "0302328212d5e430a8a880f8e2365a8f976ee50490ff030c106866c0b789eae91a",
        ]
        addresses = {pubkey_to_address(pk) for pk in pubkeys}
        self.assertEqual(len(addresses), len(pubkeys))
        self.assertTrue(all(a and a.startswith("SP") for a in addresses))


if __name__ == "__main__":
    unittest.main()
