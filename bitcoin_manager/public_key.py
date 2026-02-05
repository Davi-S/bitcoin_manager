import dataclasses

from . import secp256k1_curve
from . import private_key


@dataclasses.dataclass(frozen=True)
class PublicKey:
    """Represents a Bitcoin public key."""

    _point_raw: secp256k1_curve.Point
    _point_even_y: secp256k1_curve.Point = dataclasses.field(init=False, repr=False)
    _x_only_raw_bytes: bytes = dataclasses.field(init=False, repr=False)
    _x_only_even_y_bytes: bytes = dataclasses.field(init=False, repr=False)
    _sec1_compressed_raw_bytes: bytes = dataclasses.field(init=False, repr=False)
    _sec1_uncompressed_raw_bytes: bytes = dataclasses.field(init=False, repr=False)
    _sec1_compressed_even_y_bytes: bytes = dataclasses.field(init=False, repr=False)
    _sec1_uncompressed_even_y_bytes: bytes = dataclasses.field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Point validation is done in Point constructor
        # Create even-Y version if needed
        if self._point_raw.y % 2 == 0:
            point_even_y = self._point_raw
        else:
            point_even_y = secp256k1_curve.Point.from_coordinates(
                self._point_raw.x, secp256k1_curve.P - self._point_raw.y
            )

        x_even = point_even_y.x

        xonly_raw_bytes = self._point_raw.x.to_bytes(32, byteorder="big")
        xonly_even_y_bytes = x_even.to_bytes(32, byteorder="big")

        sec1_compressed_raw_bytes = self._point_raw.to_sec1(compressed=True)
        sec1_uncompressed_raw_bytes = self._point_raw.to_sec1(compressed=False)
        sec1_compressed_even_y_bytes = point_even_y.to_sec1(compressed=True)
        sec1_uncompressed_even_y_bytes = point_even_y.to_sec1(compressed=False)

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
        point_value = secp256k1_curve.G.multiply(private_key.to_int)
        return cls(point_value)

    @classmethod
    def from_point(cls, pt: secp256k1_curve.Point) -> "PublicKey":
        """Create from a public key point."""
        return cls(pt)

    @classmethod
    def from_sec1(cls, sec1_bytes: bytes) -> "PublicKey":
        """Create from SEC1-encoded public key bytes."""
        decoded = secp256k1_curve.sec1_decode(sec1_bytes)
        return cls(decoded)

    @property
    def to_point_raw(self) -> secp256k1_curve.Point:
        """Return the raw public key point."""
        return self._point_raw

    @property
    def to_point_even_y(self) -> secp256k1_curve.Point:
        """Return the even-Y normalized public key point."""
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
