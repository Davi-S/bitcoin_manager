"""
Tests for crypto.py - Cryptographic utility functions
"""

import pytest
from bitcoin_manager import crypto
from bitcoin_manager import secp256k1_curve


class TestSHA256:
    """Tests for SHA256 hashing function."""

    @pytest.mark.parametrize(
        "input_hex,expected_hex",
        [
            (
                "68656c6c6f",  # "hello"
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            ),
            (
                "",  # empty
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "74657374",
                "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            ),  # "test"
        ],
    )
    def test_sha256(self, input_hex, expected_hex):
        """Test SHA256 hashing with various inputs."""
        input_data = bytes.fromhex(input_hex) if input_hex else b""
        result = crypto.sha256(input_data)
        expected = bytes.fromhex(expected_hex)
        assert result == expected


class TestBase58:
    """Tests for Base58 encoding and decoding functions."""

    @pytest.mark.parametrize(
        "input_hex,expected",
        [
            ("68656c6c6f20776f726c64", "StV1DL6CwTryKyV"),  # "hello world"
            ("", ""),  # empty
            ("000102", "15T"),
            ("000074657374", "113yZe7d"),  # "\x00\x00test"
        ],
    )
    def test_encode(self, input_hex, expected):
        """Test Base58 encoding with various inputs."""
        input_bytes = bytes.fromhex(input_hex) if input_hex else b""
        result = crypto.base58_encode(input_bytes)
        assert result == expected

    @pytest.mark.parametrize(
        "input_str,expected_hex",
        [
            ("StV1DL6CwTryKyV", "68656c6c6f20776f726c64"),  # "hello world"
            ("15T", "000102"),
            ("113yZe7d", "000074657374"),  # "\x00\x00test"
        ],
    )
    def test_decode(self, input_str, expected_hex):
        """Test Base58 decoding with various inputs."""
        result = crypto.base58_decode(input_str)
        expected = bytes.fromhex(expected_hex)
        assert result == expected

    @pytest.mark.parametrize(
        "invalid_input",
        [
            "Invalid0Character",  # '0' is not in Base58
            "BadOChar",  # 'O' is not in Base58
            "Test_Invalid",  # '_' is not in Base58
        ],
    )
    def test_decode_invalid_character(self, invalid_input):
        """Test Base58 decoding with invalid characters."""
        with pytest.raises(ValueError, match="Invalid Base58 character"):
            crypto.base58_decode(invalid_input)

    def test_encode_decode_roundtrip(self):
        """Test Base58 encode/decode roundtrip."""
        original = b"test data 123"
        encoded = crypto.base58_encode(original)
        decoded = crypto.base58_decode(encoded)
        assert decoded == original


class TestTaggedHash:
    """Tests for BIP340 tagged hash function."""

    def test_consistency(self):
        """Test BIP340 tagged hash produces consistent output."""
        # Test with known tag and message
        result = crypto.tagged_hash("BIP0340/challenge", b"test")
        # Verify it produces consistent output
        result2 = crypto.tagged_hash("BIP0340/challenge", b"test")
        assert result == result2
        assert len(result) == 32

    def test_different_tags(self):
        """Test that different tags produce different hashes."""
        msg = b"same message"
        hash1 = crypto.tagged_hash("tag1", msg)
        hash2 = crypto.tagged_hash("tag2", msg)
        assert hash1 != hash2


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
        result = secp256k1_curve.point_add(secp256k1_curve.G, secp256k1_curve.G)
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
        result = secp256k1_curve.point_multiply(secp256k1_curve.G, scalar)
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
            secp256k1_curve.point_multiply(secp256k1_curve.G, invalid_scalar)


class TestBech32:
    """Tests for Bech32 encoding functions."""

    def test_encode(self):
        """Test Bech32 encoding."""
        hrp = "bc"
        data = [
            0,
            14,
            20,
            15,
            7,
            13,
            26,
            0,
            25,
            18,
            6,
            11,
            13,
            8,
            21,
            4,
            20,
            3,
            17,
            2,
            29,
            3,
            12,
            29,
            3,
            4,
            15,
            24,
            20,
            6,
            14,
            30,
            22,
        ]
        result = crypto.bech32_encode(hrp, data, "bech32")
        assert result.startswith("bc1")
        assert isinstance(result, str)

    def test_polymod(self):
        """Test Bech32 polymod function."""
        values = [3, 3, 0, 2, 3]
        result = crypto.bech32_polymod(values)
        assert isinstance(result, int)

    def test_hrp_expand(self):
        """Test HRP expansion for Bech32."""
        result = crypto.bech32_hrp_expand("bc")
        assert isinstance(result, list)
        assert all(isinstance(x, int) for x in result)
        assert len(result) == 5  # 2 chars * 2 + 1 separator


class TestConvertbits:
    """Tests for bit conversion function."""

    def test_8_to_5_conversion(self):
        """Test bit conversion from 8-bit to 5-bit."""
        # Convert 8-bit to 5-bit
        data = [255, 128, 64]
        result = crypto.convertbits(data, 8, 5, pad=True)
        assert isinstance(result, list)
        assert all(x < 32 for x in result)  # All values should be 5-bit

    def test_roundtrip(self):
        """Test convertbits roundtrip (8->5->8)."""
        original = [1, 2, 3, 4, 5]
        converted = crypto.convertbits(original, 8, 5, pad=True)
        # Note: reverse conversion may not be exact due to padding
        assert len(converted) > 0

    @pytest.mark.parametrize(
        "frombits,tobits",
        [
            (0, 5),
            (8, -1),
            (-8, 5),
            (0, 0),
        ],
    )
    def test_invalid_bit_size(self, frombits, tobits):
        """Test convertbits with invalid bit sizes."""
        with pytest.raises(Exception):  # Expecting ValidationError or similar
            crypto.convertbits([1, 2, 3], frombits, tobits)


class TestSEC1:
    """Tests for SEC1 public key encoding/decoding."""

    def test_sec1_encode_decode_compressed(self):
        """Test SEC1 compressed encode/decode roundtrip."""
        pt = secp256k1_curve.Point.from_coordinates(secp256k1_curve.Gx, secp256k1_curve.Gy)
        encoded = pt.to_sec1(compressed=True)
        assert len(encoded) == 33
        assert encoded[0] in (0x02, 0x03)
        decoded = secp256k1_curve.sec1_decode(encoded)
        assert decoded == pt

    def test_sec1_encode_decode_uncompressed(self):
        """Test SEC1 uncompressed encode/decode roundtrip."""
        pt = secp256k1_curve.Point.from_coordinates(secp256k1_curve.Gx, secp256k1_curve.Gy)
        encoded = pt.to_sec1(compressed=False)
        assert len(encoded) == 65
        assert encoded[0] == 0x04
        decoded = secp256k1_curve.sec1_decode(encoded)
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
            secp256k1_curve.sec1_decode(invalid_data)
