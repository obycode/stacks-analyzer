"""Stacks c32check address encoding, and pubkey -> address derivation.

Signer logs identify signers two different ways: acceptances carry a public key,
pre-commits carry a Stacks address. Joining the two phases for a single signer
therefore needs a mapping between them.

No lookup table is required: the address is a pure function of the public key.
Mirrors the Rust path exactly --
    StacksAddress::p2pkh(mainnet, pubkey)          types/mod.rs:1050
      -> to_bits_p2pkh  = Hash160::from_data(pubkey.to_bytes())   address/mod.rs:151
      -> Hash160        = ripemd160(sha256(data))                 util/hash.rs:182
      -> c32_address(version, hash160) = "S" + c32_check_encode()  address/c32.rs:370
with version 22 (C32_ADDRESS_VERSION_MAINNET_SINGLESIG).

Verified against the vectors in stacks-common/src/address/c32.rs::test_addresses.
"""

import hashlib
from typing import Optional

C32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

MAINNET_SINGLESIG = 22
TESTNET_SINGLESIG = 26


def _c32_encode(data: bytes) -> str:
    """Crockford-32 encode, preserving leading zero bytes as leading '0's.

    Leading zeros carry address information and must not be dropped by the
    big-integer conversion, so they are re-added explicitly.
    """
    if not data:
        return ""
    value = int.from_bytes(data, "big")
    if value == 0:
        encoded = ""
    else:
        chars = []
        while value > 0:
            value, remainder = divmod(value, 32)
            chars.append(C32_ALPHABET[remainder])
        encoded = "".join(reversed(chars))

    # Each leading zero byte contributes 8 bits of zeros; c32 carries 5 bits per
    # character. The reference implementation emits one '0' per leading zero byte.
    leading = 0
    for byte in data:
        if byte != 0:
            break
        leading += 1
    return ("0" * leading) + encoded


def c32_check_encode(version: int, data: bytes) -> str:
    if not 0 <= version < 32:
        raise ValueError("version must be 0..31")
    checksum = hashlib.sha256(
        hashlib.sha256(bytes([version]) + data).digest()
    ).digest()[:4]
    return C32_ALPHABET[version] + _c32_encode(data + checksum)


def c32_address(version: int, hash160: bytes) -> str:
    return "S" + c32_check_encode(version, hash160)


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def pubkey_to_address(pubkey_hex: str, mainnet: bool = True) -> Optional[str]:
    """Derive the signer's Stacks address from its logged public key.

    The logged key is the compressed form (33 bytes / 66 hex chars); `to_bytes()`
    on the Rust side honours the same compression flag as the `to_hex()` that
    produced the log line, so hashing the logged bytes reproduces the address.
    Returns None for anything unparseable rather than raising, since this runs
    over live log data.
    """
    if not pubkey_hex:
        return None
    try:
        raw = bytes.fromhex(pubkey_hex.strip())
    except ValueError:
        return None
    if len(raw) not in (33, 65):
        return None
    version = MAINNET_SINGLESIG if mainnet else TESTNET_SINGLESIG
    return c32_address(version, hash160(raw))
