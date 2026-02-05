import dataclasses
import typing as t

from . import crypto
from . import private_key


@dataclasses.dataclass(frozen=True)
class PublicKey:
    """Represents a Bitcoin public key."""

    _point_raw: t.Tuple[int, int]
    _point_even_y: t.Tuple[int, int] = dataclasses.field(init=False, repr=False)
    _x_only_raw_bytes: bytes = dataclasses.field(init=False, repr=False)
    _x_only_even_y_bytes: bytes = dataclasses.field(init=False, repr=False)
    _sec1_compressed_raw_bytes: bytes = dataclasses.field(init=False, repr=False)
    _sec1_uncompressed_raw_bytes: bytes = dataclasses.field(init=False, repr=False)
    _sec1_compressed_even_y_bytes: bytes = dataclasses.field(init=False, repr=False)
    _sec1_uncompressed_even_y_bytes: bytes = dataclasses.field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not crypto.is_on_curve(self._point_raw):
            raise ValueError("Public key point is not on secp256k1 curve")

        x_raw, y_raw = self._point_raw
        point_even_y = self._point_raw if y_raw % 2 == 0 else (x_raw, crypto.P - y_raw)
        x_even, _ = point_even_y

        xonly_raw_bytes = x_raw.to_bytes(32, byteorder="big")
        xonly_even_y_bytes = x_even.to_bytes(32, byteorder="big")

        sec1_compressed_raw_bytes = crypto.sec1_encode(
            self._point_raw, compressed=True
        )
        sec1_uncompressed_raw_bytes = crypto.sec1_encode(
            self._point_raw, compressed=False
        )
        sec1_compressed_even_y_bytes = crypto.sec1_encode(
            point_even_y, compressed=True
        )
        sec1_uncompressed_even_y_bytes = crypto.sec1_encode(
            point_even_y, compressed=False
        )

        object.__setattr__(self, "_point_raw", self._point_raw)
        object.__setattr__(self, "_point_even_y", point_even_y)
        object.__setattr__(self, "_x_only_raw_bytes", xonly_raw_bytes)
        object.__setattr__(self, "_x_only_even_y_bytes", xonly_even_y_bytes)
        object.__setattr__(
            self, "_sec1_compressed_raw_bytes", sec1_compressed_raw_bytes
        )
        object.__setattr__(
            self, "_sec1_uncompressed_raw_bytes", sec1_uncompressed_raw_bytes
        )
        object.__setattr__(
            self, "_sec1_compressed_even_y_bytes", sec1_compressed_even_y_bytes
        )
        object.__setattr__(
            self,
            "_sec1_uncompressed_even_y_bytes",
            sec1_uncompressed_even_y_bytes,
        )

    @classmethod
    def from_private_key(cls, private_key: private_key.PrivateKey) -> "PublicKey":
        """Create from a PrivateKey instance."""
        point = crypto.point_multiply(
            private_key.to_int, (crypto.Gx, crypto.Gy)
        )
        return cls(point)

    @classmethod
    def from_point(cls, point: t.Tuple[int, int]) -> "PublicKey":
        """Create from a public key point (x, y)."""
        return cls(point)

    @classmethod
    def from_sec1(cls, sec1_bytes: bytes) -> "PublicKey":
        """Create from SEC1-encoded public key bytes."""
        point = crypto.sec1_decode(sec1_bytes)
        return cls(point)

    @property
    def to_point_raw(self) -> t.Tuple[int, int]:
        """Return the raw public key point (x, y)."""
        return self._point_raw

    @property
    def to_point_even_y(self) -> t.Tuple[int, int]:
        """Return the even-Y normalized public key point (x, y)."""
        return self._point_even_y

    @property
    def to_x_only_raw_bytes(self) -> bytes:
        """Return the raw x-only public key bytes (32 bytes)."""
        return self._x_only_raw_bytes

    @property
    def to_x_only_even_y_bytes(self) -> bytes:
        """Return the even-Y normalized x-only public key bytes (32 bytes)."""
        return self._x_only_even_y_bytes

    @property
    def to_sec1_compressed_raw_bytes(self) -> bytes:
        """Return the SEC1 compressed public key bytes (raw point)."""
        return self._sec1_compressed_raw_bytes

    @property
    def to_sec1_uncompressed_raw_bytes(self) -> bytes:
        """Return the SEC1 uncompressed public key bytes (raw point)."""
        return self._sec1_uncompressed_raw_bytes

    @property
    def to_sec1_compressed_even_y_bytes(self) -> bytes:
        """Return the SEC1 compressed public key bytes (even-Y point)."""
        return self._sec1_compressed_even_y_bytes

    @property
    def to_sec1_uncompressed_even_y_bytes(self) -> bytes:
        """Return the SEC1 uncompressed public key bytes (even-Y point)."""
        return self._sec1_uncompressed_even_y_bytes
