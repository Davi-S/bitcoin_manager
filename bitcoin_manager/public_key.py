import typing as t

from . import crypto_utils
from . import private_key


class PublicKey:
    """Represents a Bitcoin public key."""

    def __init__(self) -> None:
        """
        Prevent direct initialization.

        """
        raise TypeError("Use PublicKey.from_* classmethods for construction")

    @classmethod
    def _from_point(cls, point_raw: crypto_utils.SECP256K1Point) -> "PublicKey":
        """
        Construct a PublicKey from a curve point.

        Args:
            point_raw: secp256k1 public key point.

        Returns:
            PublicKey instance.
        """
        instance = object.__new__(cls)
        instance._init_from_point(point_raw)
        return instance

    def _init_from_point(self, point_raw: crypto_utils.SECP256K1Point) -> None:
        """
        Initialize key state from a curve point.

        Args:
            point_raw: secp256k1 public key point.
        """
        self._point_raw = point_raw
        self._point_even_y_cache: t.Optional[crypto_utils.SECP256K1Point] = None
        self._x_only_raw_bytes_cache: t.Optional[bytes] = None
        self._x_only_even_y_bytes_cache: t.Optional[bytes] = None
        self._sec1_compressed_raw_bytes_cache: t.Optional[bytes] = None
        self._sec1_uncompressed_raw_bytes_cache: t.Optional[bytes] = None
        self._sec1_compressed_even_y_bytes_cache: t.Optional[bytes] = None
        self._sec1_uncompressed_even_y_bytes_cache: t.Optional[bytes] = None

    def _get_point_even_y(self) -> crypto_utils.SECP256K1Point:
        """
        Return an even-Y normalized version of the public key point.

        Returns:
            Public key point with even y coordinate.
        """
        if self._point_even_y_cache is None:
            if self._point_raw.y % 2 == 0:
                self._point_even_y_cache = self._point_raw
            else:
                self._point_even_y_cache = crypto_utils.SECP256K1Point.from_coordinates(
                    self._point_raw.x, crypto_utils.SECP256K1_FIELD_PRIME - self._point_raw.y
                )
        return self._point_even_y_cache

    @classmethod
    def from_private_key(cls, private_key: private_key.PrivateKey) -> "PublicKey":
        """
        Create from a PrivateKey instance.

        Args:
            private_key: PrivateKey instance.

        Returns:
            PublicKey instance.
        """
        point_value = crypto_utils.SECP256K1_GENERATOR_POINT.multiply(private_key.to_int)
        return cls._from_point(point_value)

    @classmethod
    def from_point(cls, pt: crypto_utils.SECP256K1Point) -> "PublicKey":
        """
        Create from a public key point.

        Args:
            pt: secp256k1 public key point.

        Returns:
            PublicKey instance.
        """
        return cls._from_point(pt)

    @classmethod
    def from_sec1(cls, sec1_bytes: bytes) -> "PublicKey":
        """
        Create from SEC1-encoded public key bytes.

        Args:
            sec1_bytes: SEC1-encoded public key bytes.

        Returns:
            PublicKey instance.
        """
        decoded = crypto_utils.SECP256K1Point.from_sec1(sec1_bytes)
        return cls._from_point(decoded)

    @property
    def to_point_raw(self) -> crypto_utils.SECP256K1Point:
        """
        Return the raw public key point.

        Returns:
            secp256k1 public key point.
        """
        return self._point_raw

    @property
    def to_point_even_y(self) -> crypto_utils.SECP256K1Point:
        """
        Return the even-Y normalized public key point.

        Returns:
            secp256k1 public key point with even y.
        """
        return self._get_point_even_y()

    @property
    def to_x_only_raw_bytes(self) -> bytes:
        """
        Return the raw x-only public key bytes (32 bytes).

        Returns:
            32-byte x-only public key.
        """
        if self._x_only_raw_bytes_cache is None:
            self._x_only_raw_bytes_cache = self._point_raw.x.to_bytes(
                32, byteorder="big"
            )
        return self._x_only_raw_bytes_cache

    @property
    def to_x_only_even_y_bytes(self) -> bytes:
        """
        Return the even-Y normalized x-only public key bytes (32 bytes).

        Returns:
            32-byte x-only public key with even y.
        """
        if self._x_only_even_y_bytes_cache is None:
            self._x_only_even_y_bytes_cache = self._get_point_even_y().x.to_bytes(
                32, byteorder="big"
            )
        return self._x_only_even_y_bytes_cache

    @property
    def to_sec1_compressed_raw_bytes(self) -> bytes:
        """
        Return the SEC1 compressed public key bytes (raw point).

        Returns:
            SEC1 compressed encoding of the raw point.
        """
        if self._sec1_compressed_raw_bytes_cache is None:
            self._sec1_compressed_raw_bytes_cache = self._point_raw.to_sec1_compressed
        return self._sec1_compressed_raw_bytes_cache

    @property
    def to_sec1_uncompressed_raw_bytes(self) -> bytes:
        """
        Return the SEC1 uncompressed public key bytes (raw point).

        Returns:
            SEC1 uncompressed encoding of the raw point.
        """
        if self._sec1_uncompressed_raw_bytes_cache is None:
            self._sec1_uncompressed_raw_bytes_cache = (
                self._point_raw.to_sec1_uncompressed
            )
        return self._sec1_uncompressed_raw_bytes_cache

    @property
    def to_sec1_compressed_even_y_bytes(self) -> bytes:
        """
        Return the SEC1 compressed public key bytes (even-Y point).

        Returns:
            SEC1 compressed encoding of the even-y point.
        """
        if self._sec1_compressed_even_y_bytes_cache is None:
            self._sec1_compressed_even_y_bytes_cache = (
                self._get_point_even_y().to_sec1_compressed
            )
        return self._sec1_compressed_even_y_bytes_cache

    @property
    def to_sec1_uncompressed_even_y_bytes(self) -> bytes:
        """
        Return the SEC1 uncompressed public key bytes (even-Y point).

        Returns:
            SEC1 uncompressed encoding of the even-y point.
        """
        if self._sec1_uncompressed_even_y_bytes_cache is None:
            self._sec1_uncompressed_even_y_bytes_cache = (
                self._get_point_even_y().to_sec1_uncompressed
            )
        return self._sec1_uncompressed_even_y_bytes_cache

    def __str__(self) -> str:
        """
        Return the SEC1 compressed public key as hex.

        Returns:
            Hex-encoded compressed SEC1 public key.
        """
        return self.to_sec1_compressed_raw_bytes.hex()
