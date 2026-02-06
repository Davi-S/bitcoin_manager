import typing as t

from . import hashing


# Base58 alphabet
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def int_to_le_bytes(value: int, length: int) -> bytes:
    """Serialize an integer to little-endian bytes with fixed length."""
    if value < 0:
        raise ValueError("Value must be non-negative")
    return value.to_bytes(length, byteorder="little")


def encode_varint(value: int) -> bytes:
    """Encode an integer as Bitcoin VarInt (CompactSize)."""
    if value < 0:
        raise ValueError("VarInt value must be non-negative")
    if value < 0xFD:
        return value.to_bytes(1, byteorder="little")
    if value <= 0xFFFF:
        return b"\xFD" + int_to_le_bytes(value, 2)
    if value <= 0xFFFFFFFF:
        return b"\xFE" + int_to_le_bytes(value, 4)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xFF" + int_to_le_bytes(value, 8)
    raise ValueError("VarInt value too large")


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
            f"Invalid WIF: incorrect length (expected 37 or 38 bytes, got {len(decoded)})"
        )

    # Check version byte (0x80 for mainnet)
    if decoded[0] != 0x80:
        raise ValueError(
            f"Invalid WIF: incorrect version byte (expected 0x80, got 0x{decoded[0]:02x})"
        )

    # Verify checksum (last 4 bytes)
    payload = decoded[:-4]
    checksum = decoded[-4:]
    expected_checksum = hashing.sha256(hashing.sha256(payload))[:4]
    if checksum != expected_checksum:
        raise ValueError("Invalid WIF: checksum mismatch")

    # Validate compression flag if present
    if len(decoded) == 38:
        compression_flag = payload[33]
        if compression_flag != 0x01:
            raise ValueError(
                f"Invalid WIF: invalid compression flag (expected 0x01, got 0x{compression_flag:02x})"
            )

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
    checksum = hashing.sha256(hashing.sha256(payload))[:4]

    # Encode to base58
    return base58_encode(payload + checksum)


def sat_to_btc(satoshis: int) -> float:
    """
    Convert satoshis to Bitcoin.

    Args:
        satoshis: Amount in satoshis

    Returns:
        Amount in BTC
    """
    return satoshis / 100_000_000


def btc_to_sat(btc: float) -> int:
    """
    Convert Bitcoin to satoshis.

    Args:
        btc: Amount in BTC

    Returns:
        Amount in satoshis (rounded down)
    """
    return int(btc * 100_000_000)


def decode_taproot_address(address: str) -> bytes:
    """
    Decode a Bech32m Taproot address to its scriptPubKey bytes.

    Args:
        address: Taproot address string (starts with bc1p)

    Returns:
        scriptPubKey bytes (OP_1 + 32-byte x-only pubkey)

    Raises:
        ValueError: If address format is invalid
    """
    if not isinstance(address, str):
        raise ValueError("Address must be a string")

    address_lower = address.lower()

    # Check for valid Taproot address prefix
    if not address_lower.startswith("bc1p"):
        raise ValueError("Address must start with 'bc1p' for Taproot")

    # Split into HRP and data
    if "1" not in address_lower:
        raise ValueError("Invalid Bech32 address format")

    hrp, data_part = address_lower.split("1")
    if hrp != "bc":
        raise ValueError("Invalid HRP for Bitcoin mainnet (expected 'bc')")

    # Decode using Bech32m
    try:
        data_5bit_with_checksum = [BECH32_CHARSET.index(c) for c in data_part]
    except ValueError as e:
        raise ValueError(f"Invalid Bech32 character in address: {e}") from e

    # Verify Bech32m checksum
    hrp_expanded = bech32_hrp_expand(hrp)
    values = hrp_expanded + data_5bit_with_checksum
    polymod = bech32_polymod(values)
    const = 0x2BC830A3  # Bech32m constant
    if polymod != const:
        raise ValueError("Invalid Bech32m checksum")

    # Remove checksum (last 6 characters/values)
    data_5bit = data_5bit_with_checksum[:-6]

    # First 5-bit value is witness version
    witness_version = data_5bit[0]

    # For Taproot (witness version 1), we need to convert the remaining 5-bit values
    # to 8-bit format to get the 32-byte witness program
    if witness_version != 1:
        raise ValueError(f"Expected witness version 1, got {witness_version}")

    # Convert remaining 5-bit data to 8-bit (excluding the witness version)
    data_8bit = convertbits(data_5bit[1:], 5, 8, pad=False)
    witness_program = bytes(data_8bit)

    # For Taproot (witness version 1), we need exactly 32 bytes
    if len(witness_program) != 32:
        raise ValueError(
            f"Taproot witness program must be 32 bytes, got {len(witness_program)}"
        )

    # Build scriptPubKey: OP_1 (0x51) + PUSH 32 bytes (0x20) + pubkey
    return b"\x51\x20" + witness_program
