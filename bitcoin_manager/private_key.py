import typing as t

from . import crypto_utils
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


class PrivateKey:
    """Represents a Bitcoin private key."""

    def __init__(self) -> None:
        raise TypeError("Use PrivateKey.from_* classmethods for construction")

    @classmethod
    def _from_bytes(cls, key_bytes: bytes) -> "PrivateKey":
        instance = object.__new__(cls)
        instance._init_from_bytes(key_bytes)
        return instance

    def _init_from_bytes(self, key_bytes: bytes) -> None:
        if len(key_bytes) != _KEY_LENGTH_BYTES:
            raise ValueError("Private key must be exactly 32 bytes")
        key_int = int.from_bytes(key_bytes, byteorder="big")
        if not (1 <= key_int < secp256k1_curve.SECP256K1_ORDER):
            raise ValueError("Private key is out of valid secp256k1 range")
        self._key_bytes = key_bytes
        self._key_int_cache: t.Optional[int] = None
        self._key_hex_cache: t.Optional[str] = None
        self._key_bits_cache: t.Optional[str] = None
        self._key_wif_cache: t.Optional[str] = None
        self._key_wif_compressed_cache: t.Optional[str] = None

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> "PrivateKey":
        """Create from 32 raw bytes."""
        return cls._from_bytes(key_bytes)

    @classmethod
    def from_int(cls, key_int: int) -> "PrivateKey":
        """Create from an integer."""
        key_bytes = key_int.to_bytes(_KEY_LENGTH_BYTES, byteorder="big")
        return cls._from_bytes(key_bytes)

    @classmethod
    def from_hex(cls, hex_str: str) -> "PrivateKey":
        """Create from a hex string (with or without 0x prefix)."""
        normalized = _normalize_hex(hex_str)
        return cls._from_bytes(bytes.fromhex(normalized))

    @classmethod
    def from_bits(cls, bits: str) -> "PrivateKey":
        """Create from a bit string."""
        normalized = _normalize_bits(bits)
        key_int = int(normalized, 2)
        return cls.from_int(key_int)

    @classmethod
    def from_wif(cls, wif_str: str) -> "PrivateKey":
        """Create from a WIF (Wallet Import Format) string."""
        key_bytes = crypto_utils.wif_to_bytes(wif_str)
        return cls._from_bytes(key_bytes)

    @property
    def to_bytes(self) -> bytes:
        """Return the raw 32-byte key."""
        return self._key_bytes

    @property
    def to_int(self) -> int:
        """Return the key as an integer."""
        if self._key_int_cache is None:
            self._key_int_cache = int.from_bytes(self._key_bytes, byteorder="big")
        return self._key_int_cache

    @property
    def to_hex(self) -> str:
        """Return the key as a 64-char hex string."""
        if self._key_hex_cache is None:
            self._key_hex_cache = self._key_bytes.hex()
        return self._key_hex_cache

    @property
    def to_bits(self) -> str:
        """Return the key as a 256-bit string."""
        if self._key_bits_cache is None:
            self._key_bits_cache = bin(self.to_int)[2:].rjust(_KEY_LENGTH_BYTES * 8, "0")
        return self._key_bits_cache

    @property
    def to_wif(self) -> str:
        """Return the key as an uncompressed WIF string."""
        if self._key_wif_cache is None:
            self._key_wif_cache = crypto_utils.bytes_to_wif(
                self._key_bytes, compressed=False
            )
        return self._key_wif_cache

    @property
    def to_wif_compressed(self) -> str:
        """Return the key as a compressed WIF string."""
        if self._key_wif_compressed_cache is None:
            self._key_wif_compressed_cache = crypto_utils.bytes_to_wif(
                self._key_bytes, compressed=True
            )
        return self._key_wif_compressed_cache

    def __str__(self) -> str:
        """Return the WIF compressed format of the private key."""
        return self.to_wif_compressed
