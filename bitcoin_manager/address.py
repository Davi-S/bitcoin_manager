import typing as t

from . import crypto_utils
from . import public_key
from .crypto_utils import secp256k1_curve


_TAPROOT_HRP = "bc"
_TAPROOT_WITNESS_VERSION = 1
_TAPROOT_WITNESS_PROGRAM_LEN = 32
_TAPROOT_SCRIPTPUBKEY_PREFIX = b"\x51\x20"


class TaprootAddress:
    """Represents a Taproot (P2TR) Bitcoin address."""

    def __init__(self) -> None:
        raise TypeError("Use TaprootAddress.from_* classmethods for construction")

    @classmethod
    def from_public_key(
        cls, pubkey: public_key.PublicKey, merkle_root: bytes = b""
    ) -> "TaprootAddress":
        """Create a Taproot address from a PublicKey instance."""
        if merkle_root not in (b"",):
            if len(merkle_root) != 32:
                raise ValueError("merkle_root must be 32 bytes or empty")

        public_key_point = pubkey.to_point_even_y
        internal_pubkey = pubkey.to_x_only_even_y_bytes
        tweak_hash = crypto_utils.tagged_hash(
            "TapTweak", internal_pubkey + merkle_root
        )
        tweak_int = int.from_bytes(tweak_hash, byteorder="big")
        tweak_point = secp256k1_curve.G.multiply(tweak_int)
        output_point = public_key_point.add(tweak_point)
        output_pubkey = output_point.x.to_bytes(_TAPROOT_WITNESS_PROGRAM_LEN, "big")
        instance = object.__new__(cls)
        instance._output_pubkey = output_pubkey
        instance._hrp = _TAPROOT_HRP
        instance._address_cache = None
        instance._scriptpubkey_cache = None
        return instance

    @classmethod
    def from_address(cls, address: str) -> "TaprootAddress":
        """Parse a Taproot address string into a TaprootAddress instance."""
        if not isinstance(address, str):
            raise ValueError("Address must be a string")

        address_stripped = address.strip()
        address_lower = address_stripped.lower()
        if address_lower != address_stripped and address_stripped.upper() != address_stripped:
            raise ValueError("Address must be all lower or all upper case")

        if "1" not in address_lower:
            raise ValueError("Invalid Bech32 address format")
        hrp, data_part = address_lower.split("1", 1)
        if hrp != _TAPROOT_HRP:
            raise ValueError("Invalid HRP for Bitcoin mainnet (expected 'bc')")

        try:
            data_5bit_with_checksum = [
                crypto_utils.BECH32_CHARSET.index(c) for c in data_part
            ]
        except ValueError as exc:
            raise ValueError("Invalid Bech32 character in address") from exc

        values = crypto_utils.bech32_hrp_expand(hrp) + data_5bit_with_checksum
        if crypto_utils.bech32_polymod(values) != 0x2BC830A3:
            raise ValueError("Invalid Bech32m checksum")

        data_5bit = data_5bit_with_checksum[:-6]
        if not data_5bit:
            raise ValueError("Invalid Bech32 data payload")

        witness_version = data_5bit[0]
        if witness_version != _TAPROOT_WITNESS_VERSION:
            raise ValueError("Expected witness version 1")

        data_8bit = crypto_utils.convertbits(data_5bit[1:], 5, 8, pad=False)
        witness_program = bytes(data_8bit)
        if len(witness_program) != _TAPROOT_WITNESS_PROGRAM_LEN:
            raise ValueError("Taproot witness program must be 32 bytes")
        if hrp != _TAPROOT_HRP:
            raise ValueError("Only mainnet Taproot addresses are supported")

        instance = object.__new__(cls)
        instance._output_pubkey = witness_program
        instance._hrp = hrp
        instance._address_cache = None
        instance._scriptpubkey_cache = None
        return instance

    @property
    def output_pubkey(self) -> bytes:
        """Return the x-only Taproot output key (32 bytes)."""
        return self._output_pubkey

    @property
    def hrp(self) -> str:
        return self._hrp

    def to_address(self) -> str:
        """Return the Bech32m-encoded Taproot address string."""
        if self._address_cache is None:
            witprog = crypto_utils.convertbits(list(self._output_pubkey), 8, 5)
            data = [_TAPROOT_WITNESS_VERSION] + witprog
            self._address_cache = crypto_utils.bech32_encode(
                self._hrp, data, "bech32m"
            )
        return self._address_cache

    def to_scriptpubkey(self) -> bytes:
        """Return the P2TR scriptPubKey bytes."""
        if self._scriptpubkey_cache is None:
            self._scriptpubkey_cache = _TAPROOT_SCRIPTPUBKEY_PREFIX + self._output_pubkey
        return self._scriptpubkey_cache

    def validate(self) -> None:
        """Validate the Taproot address data."""
        if len(self._output_pubkey) != _TAPROOT_WITNESS_PROGRAM_LEN:
            raise ValueError("Taproot output key must be 32 bytes")
        if self._hrp != _TAPROOT_HRP:
            raise ValueError("Only mainnet Taproot addresses are supported")

    def __str__(self) -> str:
        return self.to_address()
