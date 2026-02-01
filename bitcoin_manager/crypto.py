import hashlib
import typing as t


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
    if not data:
        return ""

    if data[0] == 0:
        return f"1{base58_encode(data[1:])}"

    x = sum(v * (256**i) for i, v in enumerate(data[::-1]))
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
    p1: t.Optional[t.Tuple[int, int]], p2: t.Optional[t.Tuple[int, int]]
) -> t.Tuple[int, int]:
    """
    Add two points on the secp256k1 elliptic curve.

    Args:
        p1: First point as (x, y) or None
        p2: Second point as (x, y) or None

    Returns:
        Sum of points as (x, y) or None if result is point at infinity
    """
    if p1 is None:
        if p2 is None:
            raise ValueError
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


def point_multiply(k: int, point: t.Tuple[int, int]) -> t.Tuple[int, int]:
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


def bech32_polymod(values: t.List[int]) -> int:
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


def bech32_hrp_expand(hrp: str) -> t.List[int]:
    """
    Expand HRP for Bech32 checksum.

    Args:
        hrp: Human-readable part

    Returns:
        List of expanded values
    """
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp: str, data: t.List[int], spec: str) -> t.List[int]:
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


def bech32_encode(hrp: str, data: t.List[int], spec: str) -> str:
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
    return f"{hrp}1" + "".join([BECH32_CHARSET[d] for d in combined])


def convertbits(
    data: t.List[int], frombits: int, tobits: int, pad: bool = True
) -> t.List[int]:
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
        raise ValueError("Bit sizes must be positive")

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
        raise ValueError("Invalid bit conversion: leftover non-zero bits")
    return ret


def wif_to_bytes(wif_str: str) -> bytes:
    """
    Decode and validate a WIF (Wallet Import Format) string.

    Args:
        wif_str: WIF string to decode

    Returns:
        Private key bytes (32 bytes)

    Raises:
        ValueError: If WIF format is invalid, checksum fails, or version byte is incorrect
    """
    cleaned = wif_str.strip()

    try:
        decoded = base58_decode(cleaned)
    except ValueError as e:
        raise ValueError("Invalid WIF: not valid base58") from e

    # WIF should be 37 bytes (uncompressed) or 38 bytes (compressed)
    # 1 byte version + 32 bytes key + 4 bytes checksum = 37 (uncompressed)
    # 1 byte version + 32 bytes key + 1 byte flag + 4 bytes checksum = 38 (compressed)
    if len(decoded) not in (37, 38):
        raise ValueError(
            f"Invalid WIF: incorrect length (expected 37 or 38 bytes, got {len(decoded)})")

    # Check version byte (0x80 for mainnet)
    if decoded[0] != 0x80:
        raise ValueError(
            f"Invalid WIF: incorrect version byte (expected 0x80, got 0x{decoded[0]:02x})")

    # Verify checksum (last 4 bytes)
    payload = decoded[:-4]
    checksum = decoded[-4:]
    expected_checksum = sha256(sha256(payload))[:4]
    if checksum != expected_checksum:
        raise ValueError("Invalid WIF: checksum mismatch")

    # Validate compression flag if present
    if len(decoded) == 38:
        compression_flag = payload[33]
        if compression_flag != 0x01:
            raise ValueError(
                f"Invalid WIF: invalid compression flag (expected 0x01, got 0x{compression_flag:02x})")

    return payload[1:33]


def bytes_to_wif(key_bytes: bytes, compressed: bool = False) -> str:
    """
    Generate a WIF (Wallet Import Format) string from private key bytes.

    Args:
        key_bytes: 32-byte private key
        compressed: Whether to include compression flag for public key

    Returns:
        WIF string
    """
    version = b"\x80"  # Mainnet
    payload = version + key_bytes

    if compressed:
        payload += b"\x01"  # Compression flag

    # Calculate checksum (first 4 bytes of double SHA256)
    checksum = sha256(sha256(payload))[:4]

    # Encode to base58
    return base58_encode(payload + checksum)
