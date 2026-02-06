import typing as t

from . import crypto_utils
from . import public_key
from .crypto_utils import secp256k1_curve


class TaprootAddress:
    """Represents a Taproot (P2TR) Bitcoin address."""

    # Class constants
    _HRP = "bc"
    _WITNESS_VERSION = 1
    _WITNESS_PROGRAM_LEN = 32
    _SCRIPTPUBKEY_PREFIX = b"\x51\x20"
    _SEPARATOR = "1"
    _CHECKSUM_CONST = 0x2BC830A3

    def __init__(self) -> None:
        raise TypeError("Use TaprootAddress.from_* classmethods for construction")

    @classmethod
    def _from_witness_program(cls, witness_program: bytes) -> "TaprootAddress":
        instance = object.__new__(cls)
        instance._init_from_witness_program(witness_program)
        return instance

    def _init_from_witness_program(self, witness_program: bytes) -> None:
        self._witness_program = witness_program
        self._checksum_cache: t.Optional[t.List[int]] = None
        self._address_cache: t.Optional[str] = None
        self._scriptpubkey_cache: t.Optional[bytes] = None
        self._validate()
        
    def _validate(self) -> None:
        """Validate the Taproot address data."""
        if len(self._witness_program) != self._WITNESS_PROGRAM_LEN:
            raise ValueError("Taproot witness program must be 32 bytes")
        
    @classmethod
    def from_public_key(
        cls, pubkey: public_key.PublicKey, merkle_root: bytes = b""
    ) -> "TaprootAddress":
        """Create a Taproot address from a PublicKey instance."""
        if merkle_root not in (b"",) and len(merkle_root) != cls._WITNESS_PROGRAM_LEN:
            raise ValueError("merkle_root must be 32 bytes or empty")

        public_key_point = pubkey.to_point_even_y
        internal_pubkey = pubkey.to_x_only_even_y_bytes
        tweak_hash = crypto_utils.tagged_hash(
            "TapTweak", internal_pubkey + merkle_root
        )
        tweak_int = secp256k1_curve.mod_secp256k1_order(
            int.from_bytes(tweak_hash, byteorder="big")
        )
        tweak_point = secp256k1_curve.G.multiply(tweak_int)
        output_point = public_key_point.add(tweak_point)
        witness_program = output_point.x.to_bytes(cls._WITNESS_PROGRAM_LEN, "big")
        return cls._from_witness_program(witness_program)

    @classmethod
    def from_address(cls, address: str) -> "TaprootAddress":
        """Parse a Taproot address string into a TaprootAddress instance."""
        if not isinstance(address, str):
            raise ValueError("Address must be a string")

        address_stripped = address.strip()
        address_lower = address_stripped.lower()
        if not address_stripped.islower() and not address_stripped.isupper():
            raise ValueError("Address must be all lower or all upper case")

        if cls._SEPARATOR not in address_lower:
            raise ValueError("Invalid Bech32 address format")
        hrp, data_part = address_lower.split(cls._SEPARATOR, 1)
        if hrp != cls._HRP:
            raise ValueError("Invalid HRP for Bitcoin mainnet (expected 'bc')")

        try:
            data_5bit_with_checksum = [
                crypto_utils.BECH32_CHARSET.index(c) for c in data_part
            ]
        except ValueError as exc:
            raise ValueError("Invalid Bech32 character in address") from exc

        values = crypto_utils.bech32_hrp_expand(hrp) + data_5bit_with_checksum
        if crypto_utils.bech32_polymod(values) != cls._CHECKSUM_CONST:
            raise ValueError("Invalid Bech32m checksum")

        data_5bit = data_5bit_with_checksum[:-6]
        if not data_5bit:
            raise ValueError("Invalid Bech32 data payload")

        witness_version = data_5bit[0]
        if witness_version != cls._WITNESS_VERSION:
            raise ValueError("Expected witness version 1")

        data_8bit = crypto_utils.convertbits(data_5bit[1:], 5, 8, pad=False)
        witness_program = bytes(data_8bit)
        if len(witness_program) != cls._WITNESS_PROGRAM_LEN:
            raise ValueError("Taproot witness program must be 32 bytes")
        if hrp != cls._HRP:
            raise ValueError("Only mainnet Taproot addresses are supported")

        return cls._from_witness_program(witness_program)

    @property
    def witness_program(self) -> bytes:
        """Return the Taproot witness program (32 bytes)."""
        return self._witness_program

    @property
    def checksum(self) -> t.List[int]:
        """Return the Bech32m checksum as a list of 5-bit integers."""
        if self._checksum_cache is None:
            witprog = crypto_utils.convertbits(list(self._witness_program), 8, 5)
            data = [self._WITNESS_VERSION] + witprog
            self._checksum_cache = crypto_utils.bech32_create_checksum(
                self._HRP, data, "bech32m"
            )
        return self._checksum_cache

    @property
    def address(self) -> str:
        """Return the Bech32m-encoded Taproot address string."""
        if self._address_cache is None:
            witprog = crypto_utils.convertbits(list(self._witness_program), 8, 5)
            data = [self._WITNESS_VERSION] + witprog
            self._address_cache = crypto_utils.bech32_encode(
                self._HRP, data, "bech32m"
            )
        return self._address_cache

    @property
    def scriptpubkey(self) -> bytes:
        """Return the P2TR scriptPubKey bytes."""
        if self._scriptpubkey_cache is None:
            self._scriptpubkey_cache = self._SCRIPTPUBKEY_PREFIX + self._witness_program
        return self._scriptpubkey_cache

    def __str__(self) -> str:
        return self.address
