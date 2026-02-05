"""
Tests for public_key.py - Bitcoin public key handling
"""

import pytest

from bitcoin_manager import secp256k1_curve
from bitcoin_manager import private_key
from bitcoin_manager import public_key


class TestPublicKeyCreation:
    """Tests for PublicKey creation methods."""

    def test_from_private_key(self):
        """Test creating PublicKey from PrivateKey."""
        key_hex = "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        pk = private_key.PrivateKey.from_hex(key_hex)
        pub = public_key.PublicKey.from_private_key(pk)

        expected_point = secp256k1_curve.G.multiply(pk.to_int)
        assert pub.to_point_raw == expected_point

        y_raw = expected_point.y
        expected_even = (
            expected_point
            if y_raw % 2 == 0
            else secp256k1_curve.Point.from_coordinates(
                expected_point.x, secp256k1_curve.P - y_raw
            )
        )
        assert pub.to_point_even_y == expected_even

    def test_from_point(self):
        """Test creating PublicKey from explicit point."""
        pt = secp256k1_curve.Point.from_coordinates(
            secp256k1_curve.Gx, secp256k1_curve.Gy
        )
        pub = public_key.PublicKey.from_point(pt)
        assert pub.to_point_raw == pt

    def test_from_point_invalid(self):
        """Test invalid point raises ValueError."""
        with pytest.raises(ValueError, match="Point is not on the secp256k1 curve"):
            secp256k1_curve.Point.from_coordinates(1, 1)

    def test_from_sec1(self):
        """Test creating PublicKey from SEC1 bytes."""
        pt = secp256k1_curve.Point.from_coordinates(
            secp256k1_curve.Gx, secp256k1_curve.Gy
        )
        sec1_bytes = pt.to_sec1(compressed=True)
        pub = public_key.PublicKey.from_sec1(sec1_bytes)
        assert pub.to_point_raw == pt


class TestPublicKeyRepresentations:
    """Tests for PublicKey representations."""

    def test_representations(self):
        """Test PublicKey representation outputs."""
        pt = secp256k1_curve.Point.from_coordinates(
            secp256k1_curve.Gx, secp256k1_curve.Gy
        )
        pub = public_key.PublicKey.from_point(pt)

        x_bytes = pt.x.to_bytes(32, byteorder="big")

        y_raw = pt.y
        even_point = (
            pt
            if y_raw % 2 == 0
            else secp256k1_curve.Point.from_coordinates(pt.x, secp256k1_curve.P - y_raw)
        )

        assert pub.to_x_only_raw_bytes == x_bytes
        assert pub.to_x_only_even_y_bytes == even_point.x.to_bytes(32, byteorder="big")
        assert pub.to_sec1_compressed_raw_bytes == secp256k1_curve.sec1_encode(
            pt, compressed=True
        )
        assert pub.to_sec1_uncompressed_raw_bytes == secp256k1_curve.sec1_encode(
            pt, compressed=False
        )
        assert pub.to_sec1_compressed_even_y_bytes == secp256k1_curve.sec1_encode(
            even_point, compressed=True
        )
        assert pub.to_sec1_uncompressed_even_y_bytes == secp256k1_curve.sec1_encode(
            even_point, compressed=False
        )
