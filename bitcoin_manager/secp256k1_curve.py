import dataclasses


# Secp256k1 curve parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Secp256k1 order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclasses.dataclass(frozen=True)
class Point:
    """Represents a point on the secp256k1 elliptic curve."""

    x: int
    y: int

    def __post_init__(self) -> None:
        """Validate point coordinates on initialization."""
        if not (0 <= self.x < P and 0 <= self.y < P):
            raise ValueError("Point coordinates out of field range")

        # Check curve equation: y² ≡ x³ + 7 (mod P)
        if (self.y * self.y - (self.x * self.x * self.x + 7)) % P != 0:
            raise ValueError("Point is not on the secp256k1 curve")

    @classmethod
    def from_coordinates(cls, x: int, y: int) -> "Point":
        """Create a Point from x and y coordinates."""
        return cls(x=x, y=y)

    def add(self, other: "Point") -> "Point":
        """
        Add this point to another point.

        Args:
            other: Another Point to add

        Returns:
            Result of point addition

        Raises:
            ValueError: If adding a point to its inverse (point at infinity)
        """
        if not isinstance(other, Point):
            raise TypeError("Can only add Point to Point")

        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y

        if x1 == x2:
            if y1 == y2:
                # Point doubling: P + P
                s = (3 * x1 * x1 * pow(2 * y1, P - 2, P)) % P
            else:
                # P + (-P) = point at infinity
                raise ValueError("Cannot add point to its inverse (point at infinity)")
        else:
            # Regular addition: (y2 - y1) / (x2 - x1)
            s = ((y2 - y1) * pow(x2 - x1, P - 2, P)) % P

        x3 = (s * s - x1 - x2) % P
        y3 = (s * (x1 - x3) - y1) % P
        return Point.from_coordinates(x3, y3)

    def multiply(self, k: int) -> "Point":
        """
        Multiply this point by a scalar using double-and-add algorithm.

        Args:
            k: Scalar multiplier

        Returns:
            Result point k*P

        Raises:
            ValueError: If scalar is not positive
        """
        if not isinstance(k, int) or k <= 0:
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

    def to_sec1(self, compressed: bool = True) -> bytes:
        """
        Encode to SEC1 format.

        Args:
            compressed: Whether to use compressed format (33 bytes) or uncompressed (65 bytes)

        Returns:
            SEC1-encoded bytes
        """
        x_bytes = self.x.to_bytes(32, byteorder="big")
        y_bytes = self.y.to_bytes(32, byteorder="big")

        if compressed:
            prefix = b"\x02" if self.y % 2 == 0 else b"\x03"
            return prefix + x_bytes

        return b"\x04" + x_bytes + y_bytes

    @staticmethod
    def from_sec1(data: bytes) -> "Point":
        """
        Decode from SEC1-encoded bytes.

        Args:
            data: SEC1-encoded bytes (33 bytes compressed or 65 bytes uncompressed)

        Returns:
            Point decoded from SEC1 format

        Raises:
            ValueError: If SEC1 format is invalid
        """
        if len(data) == 33:
            prefix = data[0]
            if prefix not in (0x02, 0x03):
                raise ValueError("Invalid SEC1 compressed prefix")

            x = int.from_bytes(data[1:], byteorder="big")
            if x >= P:
                raise ValueError("Invalid SEC1 x-coordinate")

            y_sq = (pow(x, 3, P) + 7) % P
            y = pow(y_sq, (P + 1) // 4, P)
            if (y * y) % P != y_sq:
                raise ValueError("Invalid SEC1 compressed point")

            if (y % 2 == 0) != (prefix == 0x02):
                y = P - y

            return Point.from_coordinates(x, y)

        if len(data) == 65:
            if data[0] != 0x04:
                raise ValueError("Invalid SEC1 uncompressed prefix")

            x = int.from_bytes(data[1:33], byteorder="big")
            y = int.from_bytes(data[33:], byteorder="big")
            if x >= P or y >= P:
                raise ValueError("Invalid SEC1 uncompressed coordinates")

            return Point.from_coordinates(x, y)

        raise ValueError("Invalid SEC1 length")

    def __eq__(self, other: object) -> bool:
        """Check equality with another Point."""
        if not isinstance(other, Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y

    def __repr__(self) -> str:
        """String representation of the point."""
        return f"Point(0x{self.x:064x}, 0x{self.y:064x})"


# Generator point G for secp256k1
G = Point.from_coordinates(Gx, Gy)


def point_add(p1: Point, p2: Point) -> Point:
    """
    Add two points on the secp256k1 elliptic curve.

    Args:
        p1: First point
        p2: Second point

    Returns:
        Sum of points

    Raises:
        ValueError: If adding a point to its inverse
    """
    return p1.add(p2)


def point_multiply(point: Point, k: int) -> Point:
    """
    Multiply a point by a scalar using double-and-add algorithm.

    Args:
        k: Scalar multiplier
        point: Point to multiply

    Returns:
        Product point

    Raises:
        ValueError: If scalar is invalid or multiplication results in infinity
    """
    return point.multiply(k)


def sec1_encode(point: Point, compressed: bool = True) -> bytes:
    """
    Encode a secp256k1 point to SEC1 format.

    Args:
        point: Point to encode
        compressed: Whether to use compressed SEC1 format

    Returns:
        SEC1-encoded bytes
    """
    return point.to_sec1(compressed)


def sec1_decode(data: bytes) -> Point:
    """
    Decode a SEC1-encoded secp256k1 public key into a point.

    Args:
        data: SEC1-encoded bytes

    Returns:
        Decoded point
    """
    return Point.from_sec1(data)
