import hashlib
from typing import Tuple, Optional, List


# Secp256k1 curve parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Secp256k1 order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Base58 alphabet
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def sha256(data: bytes) -> bytes:
    """
    Compute SHA256 hash of data.

    Args:
        data: Bytes to hash

    Returns:
        SHA256 digest as bytes
    """
    digest = hashlib.new("sha256")
    digest.update(data)
    return digest.digest()


def base58_encode(data: bytes) -> str:
    """
    Encode bytes to Base58 string.

    Args:
        data: Bytes to encode

    Returns:
        Base58 encoded string
    """
    if len(data) == 0:
        return ""

    if data[0] == 0:
        return "1" + base58_encode(data[1:])

    x = sum([v * (256**i) for i, v in enumerate(data[::-1])])
    ret = ""
    while x > 0:
        ret = B58_ALPHABET[x % 58] + ret
        x = x // 58

    return ret


def base58_decode(value: str) -> bytes:
    """
    Decode a Base58 string to bytes.

    Args:
        value: Base58 string

    Returns:
        Decoded bytes
    """
    num = 0
    for char in value:
        num *= 58
        try:
            num += B58_ALPHABET.index(char)
        except ValueError as exc:
            raise ValueError(f"Invalid Base58 character: {char}") from exc

    full_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big")

    pad = 0
    for char in value:
        if char == "1":
            pad += 1
        else:
            break

    return b"\x00" * pad + full_bytes


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """
    Compute BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).

    Args:
        tag: Tag string for the hash
        msg: Message bytes to hash

    Returns:
        Tagged hash digest as bytess
    """
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + msg)


def point_add(
    p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]
) -> Tuple[int, int]:
    """
    Add two points on the secp256k1 elliptic curve.

    Args:
        p1: First point as (x, y) or None
        p2: Second point as (x, y) or None

    Returns:
        Sum of points as (x, y) or None if result is point at infinity
    """
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2:
        if y1 == y2:
            # Point doubling
            s = (3 * x1 * x1 * pow(2 * y1, P - 2, P)) % P
        else:
            raise Exception(
                "This should not happen: Adding a point P to its inverse -P"
            )
    else:
        s = ((y2 - y1) * pow(x2 - x1, P - 2, P)) % P

    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)


def point_multiply(k: int, point: Tuple[int, int]) -> Tuple[int, int]:
    """
    Multiply a point by a scalar using double-and-add algorithm.

    Args:
        k: Scalar multiplier
        point: Point as (x, y)

    Returns:
        Product point as (x, y) or None
    """
    if k <= 0:
        raise ValueError("Scalar must be an integer greater than 0")

    addend = point
    result = None

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


def bech32_polymod(values: List[int]) -> int:
    """
    Internal function for Bech32/Bech32m checksum.

    Args:
        values: List of integer values

    Returns:
        Polymod checksum value
    """
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> List[int]:
    """
    Expand HRP for Bech32 checksum.

    Args:
        hrp: Human-readable part

    Returns:
        List of expanded values
    """
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp: str, data: List[int], spec: str) -> List[int]:
    """
    Create checksum for Bech32 or Bech32m.

    Args:
        hrp: Human-readable part
        data: Data to checksum
        spec: Specification ("bech32" or "bech32m")

    Returns:
        Checksum as list of integers
    """
    values = bech32_hrp_expand(hrp) + data
    const = 0x2BC830A3 if spec == "bech32m" else 1
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: List[int], spec: str) -> str:
    """
    Encode data using Bech32 or Bech32m.

    Args:
        hrp: Human-readable part
        data: Data to encode (as 5-bit values)
        spec: Specification ("bech32" or "bech32m")

    Returns:
        Bech32 encoded string

    """
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in combined])


def convertbits(
    data: List[int], frombits: int, tobits: int, pad: bool = True
) -> List[int]:
    """
    Convert between bit groups.

    Args:
        data: Input data as list of integers
        frombits: Source bit group size
        tobits: Target bit group size
        pad: Whether to pad the result

    Returns:
        Converted data
    """
    if frombits <= 0 or tobits <= 0:
        raise ValidationError("Bit sizes must be positive")

    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValidationError("Invalid bit conversion: leftover non-zero bits")
    return ret
