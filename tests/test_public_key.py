"""
Tests for public_key.py - Bitcoin public key handling
"""

import pytest

from bitcoin_manager import crypto
from bitcoin_manager import private_key
from bitcoin_manager import public_key


class TestPublicKeyCreation:
    """Tests for PublicKey creation methods."""

    def test_from_private_key(self):
        """Test creating PublicKey from PrivateKey."""
        key_hex = (
            "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        )
        pk = private_key.PrivateKey.from_hex(key_hex)
        pub = public_key.PublicKey.from_private_key(pk)

        expected_point = crypto.point_multiply(pk.to_int, (crypto.Gx, crypto.Gy))
        assert pub.to_point_raw == expected_point

        x_raw, y_raw = expected_point
        expected_even = expected_point if y_raw % 2 == 0 else (x_raw, crypto.P - y_raw)
        assert pub.to_point_even_y == expected_even

    def test_from_point(self):
        """Test creating PublicKey from explicit point."""
        point = (crypto.Gx, crypto.Gy)
        pub = public_key.PublicKey.from_point(point)
        assert pub.to_point_raw == point

    def test_from_point_invalid(self):
        """Test invalid point raises ValueError."""
        with pytest.raises(ValueError, match="Public key point is not on secp256k1 curve"):
            public_key.PublicKey.from_point((1, 1))

    def test_from_sec1(self):
        """Test creating PublicKey from SEC1 bytes."""
        point = (crypto.Gx, crypto.Gy)
        sec1_bytes = crypto.sec1_encode(point, compressed=True)
        pub = public_key.PublicKey.from_sec1(sec1_bytes)
        assert pub.to_point_raw == point


class TestPublicKeyRepresentations:
    """Tests for PublicKey representations."""

    def test_representations(self):
        """Test PublicKey representation outputs."""
        point = (crypto.Gx, crypto.Gy)
        pub = public_key.PublicKey.from_point(point)

        x_raw, y_raw = point
        x_bytes = x_raw.to_bytes(32, byteorder="big")

        even_point = point if y_raw % 2 == 0 else (x_raw, crypto.P - y_raw)
        
        assert pub.to_x_only_raw_bytes == x_bytes
        assert pub.to_x_only_even_y_bytes == even_point[0].to_bytes(32, byteorder="big")
        assert pub.to_sec1_compressed_raw_bytes == crypto.sec1_encode(point, compressed=True)
        assert pub.to_sec1_uncompressed_raw_bytes == crypto.sec1_encode(point, compressed=False)
        assert pub.to_sec1_compressed_even_y_bytes == crypto.sec1_encode(even_point, compressed=True)
        assert pub.to_sec1_uncompressed_even_y_bytes == crypto.sec1_encode(even_point, compressed=False)
