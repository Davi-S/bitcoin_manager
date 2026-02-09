from __future__ import annotations

# Secp256k1 curve parameters
SECP256K1_FIELD_PRIME = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
)
SECP256K1_CURVE_ORDER = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)
SECP256K1_GENERATOR_POINT_X = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
)
SECP256K1_GENERATOR_POINT_Y = (
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
)

# Secp256k1 order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class SECP256K1Point:
    """Represents a point on the secp256k1 elliptic curve."""

    def __init__(self) -> None:
        """
        Prevent direct initialization.

        """
        raise TypeError("Use Point.from_* classmethods for construction")

    @classmethod
    def _from_coordinates(cls, x: int, y: int) -> SECP256K1Point:
        """
        Construct a point instance without validation checks.

        Args:
            x: X coordinate.
            y: Y coordinate.

        Returns:
            A new point instance.
        """
        instance = object.__new__(cls)
        instance._init_from_coordinates(x, y)
        return instance

    def _init_from_coordinates(self, x: int, y: int) -> None:
        """
        Initialize point coordinates and validate curve membership.

        Args:
            x: X coordinate.
            y: Y coordinate.
        """
        self._x = x
        self._y = y
        self._sec1_compressed_cache: bytes | None = None
        self._sec1_uncompressed_cache: bytes | None = None
        self._validate()

    def _validate(self) -> None:
        """
        Validate point coordinates on initialization.

        """
        if not (
            0 <= self._x < SECP256K1_FIELD_PRIME
            and 0 <= self._y < SECP256K1_FIELD_PRIME
        ):
            raise ValueError("Point coordinates out of field range")

        # Check curve equation: y^2 = x^3 + 7 (mod P)
        if (
            self._y * self._y - (self._x * self._x * self._x + 7)
        ) % SECP256K1_FIELD_PRIME != 0:
            raise ValueError("Point is not on the secp256k1 curve")

    @classmethod
    def from_coordinates(cls, x: int, y: int) -> SECP256K1Point:
        """
        Create a Point from x and y coordinates.

        Args:
            x: X coordinate.
            y: Y coordinate.

        Returns:
            Point instance on the curve.
        """
        return cls._from_coordinates(x, y)

    @classmethod
    def from_sec1(cls, data: bytes) -> SECP256K1Point:
        """
        Decode from SEC1-encoded bytes.

        Args:
            data: SEC1-encoded bytes (33 bytes compressed or 65 bytes uncompressed)

        Returns:
            Point decoded from SEC1 format

        """
        if len(data) == 33:
            prefix = data[0]
            if prefix not in (0x02, 0x03):
                raise ValueError("Invalid SEC1 compressed prefix")

            x = int.from_bytes(data[1:], byteorder="big")
            if x >= SECP256K1_FIELD_PRIME:
                raise ValueError("Invalid SEC1 x-coordinate")

            y_sq = (pow(x, 3, SECP256K1_FIELD_PRIME) + 7) % SECP256K1_FIELD_PRIME
            y = pow(y_sq, (SECP256K1_FIELD_PRIME + 1) // 4, SECP256K1_FIELD_PRIME)
            if (y * y) % SECP256K1_FIELD_PRIME != y_sq:
                raise ValueError("Invalid SEC1 compressed point")

            if (y % 2 == 0) != (prefix == 0x02):
                y = SECP256K1_FIELD_PRIME - y

            return cls.from_coordinates(x, y)

        if len(data) == 65:
            if data[0] != 0x04:
                raise ValueError("Invalid SEC1 uncompressed prefix")

            x = int.from_bytes(data[1:33], byteorder="big")
            y = int.from_bytes(data[33:], byteorder="big")
            if x >= SECP256K1_FIELD_PRIME or y >= SECP256K1_FIELD_PRIME:
                raise ValueError("Invalid SEC1 uncompressed coordinates")

            return cls.from_coordinates(x, y)

        raise ValueError("Invalid SEC1 length")

    @property
    def x(self) -> int:
        """
        Return the x coordinate.

        Returns:
            X coordinate.
        """
        return self._x

    @property
    def y(self) -> int:
        """
        Return the y coordinate.

        Returns:
            Y coordinate.
        """
        return self._y

    @property
    def to_sec1_compressed(self) -> bytes:
        """
        Encode to SEC1 compressed format (33 bytes).

        Returns:
            SEC1 compressed-encoded bytes
        """
        if self._sec1_compressed_cache is None:
            x_bytes = self.x.to_bytes(32, byteorder="big")
            prefix = b"\x02" if self.y % 2 == 0 else b"\x03"
            self._sec1_compressed_cache = prefix + x_bytes
        return self._sec1_compressed_cache

    @property
    def to_sec1_uncompressed(self) -> bytes:
        """
        Encode to SEC1 uncompressed format (65 bytes).

        Returns:
            SEC1 uncompressed-encoded bytes
        """
        if self._sec1_uncompressed_cache is None:
            x_bytes = self.x.to_bytes(32, byteorder="big")
            y_bytes = self.y.to_bytes(32, byteorder="big")
            self._sec1_uncompressed_cache = b"\x04" + x_bytes + y_bytes
        return self._sec1_uncompressed_cache

    def add(self, other: SECP256K1Point) -> SECP256K1Point:
        """
        Add this point to another point.

        Args:
            other: Another Point to add

        Returns:
            Result of point addition

        """
        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y

        if x1 == x2:
            if y1 == y2:
                # Point doubling: P + P
                s = (
                    3
                    * x1
                    * x1
                    * pow(2 * y1, SECP256K1_FIELD_PRIME - 2, SECP256K1_FIELD_PRIME)
                ) % SECP256K1_FIELD_PRIME
            else:
                # P + (-P) = point at infinity
                raise ValueError("Cannot add point to its inverse (point at infinity)")
        else:
            # Regular addition: (y2 - y1) / (x2 - x1)
            s = (
                (y2 - y1)
                * pow(x2 - x1, SECP256K1_FIELD_PRIME - 2, SECP256K1_FIELD_PRIME)
            ) % SECP256K1_FIELD_PRIME

        x3 = (s * s - x1 - x2) % SECP256K1_FIELD_PRIME
        y3 = (s * (x1 - x3) - y1) % SECP256K1_FIELD_PRIME
        return SECP256K1Point.from_coordinates(x3, y3)

    def multiply(self, k: int) -> SECP256K1Point:
        """
        Multiply this point by a scalar using double-and-add algorithm.

        Args:
            k: Scalar multiplier

        Returns:
            Result point k*P

        """
        if k <= 0:
            raise ValueError("Scalar must be an integer greater than 0")

        addend = self
        result = None  # type: ignore

        while k:
            if k & 1:
                result = addend if result is None else result.add(addend)
            addend = addend.add(addend)
            k >>= 1

        if result is None:
            raise ValueError("Scalar multiplication resulted in point at infinity")

        return result

    def negate(self) -> SECP256K1Point:
        """
        Return the negation of this point.

        Returns:
            Point with the same x and negated y coordinate.
        """
        return SECP256K1Point.from_coordinates(self.x, SECP256K1_FIELD_PRIME - self.y)

    def __eq__(self, other: object) -> bool:
        """
        Check equality with another Point.

        Args:
            other: Object to compare against.

        Returns:
            True if other is a SECP256K1Point with equal coordinates.
        """
        if not isinstance(other, SECP256K1Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y

    def __hash__(self) -> int:
        """
        Return hash of the point.

        Returns:
            Hash value for use in hash-based collections.
        """
        return hash((self.x, self.y))

    def __repr__(self) -> str:
        """
        Return a debug representation of the point.

        Returns:
            String representation with hex coordinates.
        """
        return f"Point(0x{self.x:064x}, 0x{self.y:064x})"


# Generator point G for secp256k1
SECP256K1_GENERATOR_POINT = SECP256K1Point.from_coordinates(
    SECP256K1_GENERATOR_POINT_X, SECP256K1_GENERATOR_POINT_Y
)
