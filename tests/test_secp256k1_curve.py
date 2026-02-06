"""
Tests for secp256k1_curve.py - Elliptic curve operations
"""

import pytest
from bitcoin_manager import secp256k1_curve


class TestPointOperations:
    """Tests for elliptic curve point operations."""

    def test_point_add_with_point_objects(self):
        """Test point addition with Point objects."""
        point1 = secp256k1_curve.G
        point2 = secp256k1_curve.G

        # Add two Point objects
        result = point1.add(point2)
        assert isinstance(result, secp256k1_curve.Point)
        assert result.x > 0
        assert result.y > 0

    def test_point_add(self):
        """Test point addition on secp256k1 curve."""
        # Use generator point
        result = secp256k1_curve.G.add(secp256k1_curve.G)
        assert result is not None
        assert isinstance(result, secp256k1_curve.Point)
        assert result.x > 0
        assert result.y > 0

    @pytest.mark.parametrize(
        "scalar",
        [1, 2, 3, 5, 10, 100],
    )
    def test_point_multiply(self, scalar):
        """Test point multiplication on secp256k1 curve."""
        result = secp256k1_curve.G.multiply(scalar)
        assert result is not None
        assert isinstance(result, secp256k1_curve.Point)
        assert result.x > 0
        assert result.y > 0

    def test_point_multiply_with_point_object(self):
        """Test point multiplication with Point object."""
        result = secp256k1_curve.G.multiply(5)
        assert isinstance(result, secp256k1_curve.Point)
        assert result.x > 0
        assert result.y > 0

    @pytest.mark.parametrize(
        "invalid_scalar",
        [0, -1, -5, -100],
    )
    def test_point_multiply_invalid_scalar(self, invalid_scalar):
        """Test point multiplication with invalid scalars."""
        with pytest.raises(
            ValueError, match="Scalar must be an integer greater than 0"
        ):
            secp256k1_curve.G.multiply(invalid_scalar)


class TestSEC1:
    """Tests for SEC1 public key encoding/decoding."""

    def test_sec1_encode_decode_compressed(self):
        """Test SEC1 compressed encode/decode roundtrip."""
        pt = secp256k1_curve.Point.from_coordinates(
            secp256k1_curve.Gx, secp256k1_curve.Gy
        )
        encoded = pt.to_sec1_compressed
        assert len(encoded) == 33
        assert encoded[0] in (0x02, 0x03)
        decoded = secp256k1_curve.Point.from_sec1(encoded)
        assert decoded == pt

    def test_sec1_encode_decode_uncompressed(self):
        """Test SEC1 uncompressed encode/decode roundtrip."""
        pt = secp256k1_curve.Point.from_coordinates(
            secp256k1_curve.Gx, secp256k1_curve.Gy
        )
        encoded = pt.to_sec1_uncompressed
        assert len(encoded) == 65
        assert encoded[0] == 0x04
        decoded = secp256k1_curve.Point.from_sec1(encoded)
        assert decoded == pt

    @pytest.mark.parametrize(
        "invalid_data,error_match",
        [
            (b"", "Invalid SEC1 length"),
            (b"\x01" + b"\x00" * 32, "Invalid SEC1 compressed prefix"),
            (b"\x04" + b"\x00" * 32, "Invalid SEC1 compressed prefix"),
        ],
    )
    def test_sec1_decode_invalid(self, invalid_data, error_match):
        """Test SEC1 decoding rejects invalid inputs."""
        with pytest.raises(ValueError, match=error_match):
            secp256k1_curve.Point.from_sec1(invalid_data)
