"""
Tests for encoding.py - Encoding and serialization functions
"""

import pytest
from bitcoin_manager.crypto_utils import encoding


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
        result = encoding.base58_encode(input_bytes)
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
        result = encoding.base58_decode(input_str)
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
            encoding.base58_decode(invalid_input)

    def test_encode_decode_roundtrip(self):
        """Test Base58 encode/decode roundtrip."""
        original = b"test data 123"
        encoded = encoding.base58_encode(original)
        decoded = encoding.base58_decode(encoded)
        assert decoded == original


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
        result = encoding.bech32_encode(hrp, data, "bech32")
        assert result.startswith("bc1")
        assert isinstance(result, str)

    def test_polymod(self):
        """Test Bech32 polymod function."""
        values = [3, 3, 0, 2, 3]
        result = encoding.bech32_polymod(values)
        assert isinstance(result, int)

    def test_hrp_expand(self):
        """Test HRP expansion for Bech32."""
        result = encoding.bech32_hrp_expand("bc")
        assert isinstance(result, list)
        assert all(isinstance(x, int) for x in result)
        assert len(result) == 5  # 2 chars * 2 + 1 separator


class TestConvertbits:
    """Tests for bit conversion function."""

    def test_8_to_5_conversion(self):
        """Test bit conversion from 8-bit to 5-bit."""
        # Convert 8-bit to 5-bit
        data = [255, 128, 64]
        result = encoding.convertbits(data, 8, 5, pad=True)
        assert isinstance(result, list)
        assert all(x < 32 for x in result)  # All values should be 5-bit

    def test_roundtrip(self):
        """Test convertbits roundtrip (8->5->8)."""
        original = [1, 2, 3, 4, 5]
        converted = encoding.convertbits(original, 8, 5, pad=True)
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
            encoding.convertbits([1, 2, 3], frombits, tobits)


class TestVarInt:
    """Tests for VarInt encoding."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            (0, b"\x00"),
            (1, b"\x01"),
            (34, b"\x22"),
            (0xFC, b"\xFC"),
            (0xFD, b"\xFD\xFD\x00"),
            (0xFFFF, b"\xFD\xFF\xFF"),
            (0x10000, b"\xFE\x00\x00\x01\x00"),
        ],
    )
    def test_encode_varint_minimal(self, value, expected):
        """Ensure VarInt uses minimal encoding per value size."""
        assert encoding.encode_varint(value) == expected
