import dataclasses

from . import crypto
from . import secp256k1_curve


_KEY_LENGTH_BYTES = 32


def _normalize_hex(hex_str: str) -> str:
    cleaned = "".join(hex_str.strip().split()).lower()
    cleaned = cleaned.removeprefix("0x")
    if any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError("Hex string contains non-hex characters")
    if len(cleaned) > _KEY_LENGTH_BYTES * 2:
        raise ValueError("Hex string is longer than 32 bytes")
    return cleaned.rjust(_KEY_LENGTH_BYTES * 2, "0")


def _normalize_bits(bits: str) -> str:
    cleaned = "".join(bits.strip().split())
    if not cleaned:
        raise ValueError("Bit string is empty")
    if any(c not in "01" for c in cleaned):
        raise ValueError("Bit string contains non-bit characters")
    if len(cleaned) > _KEY_LENGTH_BYTES * 8:
        raise ValueError("Bit string is longer than 256 bits")
    return cleaned


@dataclasses.dataclass(frozen=True)
class PrivateKey:
    """Represents a Bitcoin private key."""

    _key_bytes: bytes
    _key_int: int = dataclasses.field(init=False, repr=False)
    _key_hex: str = dataclasses.field(init=False, repr=False)
    _key_bits: str = dataclasses.field(init=False, repr=False)
    _key_wif: str = dataclasses.field(init=False, repr=False)
    _key_wif_compressed: str = dataclasses.field(init=False, repr=False)

    def __post_init__(self) -> None:
        if len(self._key_bytes) != _KEY_LENGTH_BYTES:
            raise ValueError("Private key must be exactly 32 bytes")
        key_int = int.from_bytes(self._key_bytes, byteorder="big")
        if not (1 <= key_int < secp256k1_curve.SECP256K1_ORDER):
            raise ValueError("Private key is out of valid secp256k1 range")
        object.__setattr__(self, "_key_bytes", self._key_bytes)
        object.__setattr__(self, "_key_int", key_int)
        object.__setattr__(self, "_key_hex", self._key_bytes.hex())
        object.__setattr__(
            self, "_key_bits", bin(key_int)[2:].rjust(
                _KEY_LENGTH_BYTES * 8, "0")
        )
        # Generate WIF formats
        object.__setattr__(self, "_key_wif", crypto.bytes_to_wif(
            self._key_bytes, compressed=False))
        object.__setattr__(self, "_key_wif_compressed",
                           crypto.bytes_to_wif(self._key_bytes, compressed=True))

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> "PrivateKey":
        """Create from 32 raw bytes."""
        return cls(key_bytes)

    @classmethod
    def from_int(cls, key_int: int) -> "PrivateKey":
        """Create from an integer."""
        key_bytes = key_int.to_bytes(_KEY_LENGTH_BYTES, byteorder="big")
        return cls(key_bytes)

    @classmethod
    def from_hex(cls, hex_str: str) -> "PrivateKey":
        """Create from a hex string (with or without 0x prefix)."""
        normalized = _normalize_hex(hex_str)
        return cls(bytes.fromhex(normalized))

    @classmethod
    def from_bits(cls, bits: str) -> "PrivateKey":
        """Create from a bit string."""
        normalized = _normalize_bits(bits)
        key_int = int(normalized, 2)
        return cls.from_int(key_int)

    @classmethod
    def from_wif(cls, wif_str: str) -> "PrivateKey":
        """Create from a WIF (Wallet Import Format) string."""
        key_bytes = crypto.wif_to_bytes(wif_str)
        return cls(key_bytes)

    @property
    def to_bytes(self) -> bytes:
        """Return the raw 32-byte key."""
        return self._key_bytes

    @property
    def to_int(self) -> int:
        """Return the key as an integer."""
        return self._key_int

    @property
    def to_hex(self) -> str:
        """Return the key as a 64-char hex string."""
        return self._key_hex

    @property
    def to_bits(self) -> str:
        """Return the key as a 256-bit string."""
        return self._key_bits

    @property
    def to_wif(self) -> str:
        """Return the key as an uncompressed WIF string."""
        return self._key_wif

    @property
    def to_wif_compressed(self) -> str:
        """Return the key as a compressed WIF string."""
        return self._key_wif_compressed

    def __str__(self) -> str:
        """Return the WIF compressed format of the private key."""
        return self._key_wif_compressed
