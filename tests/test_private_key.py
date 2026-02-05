"""
Tests for private_key.py - Bitcoin private key handling
"""

import pytest
from bitcoin_manager import secp256k1_curve
from bitcoin_manager import private_key


class TestPrivateKeyCreation:
    """Tests for PrivateKey creation methods."""

    def test_from_bytes(self):
        """Test creating PrivateKey from bytes."""
        key_bytes = bytes.fromhex(
            "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        )
        pk = private_key.PrivateKey.from_bytes(key_bytes)
        assert pk.to_bytes == key_bytes

    def test_from_int(self):
        """Test creating PrivateKey from integer."""
        key_int = 12345678901234567890
        pk = private_key.PrivateKey.from_int(key_int)
        assert pk.to_int == key_int

    @pytest.mark.parametrize(
        "hex_input,expected_hex",
        [
            (
                "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e",
                "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e",
            ),
            (
                "0x7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e",
                "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e",
            ),
            (
                "1234",
                "0000000000000000000000000000000000000000000000000000000000001234",
            ),
            (
                "0xABCD",
                "000000000000000000000000000000000000000000000000000000000000abcd",
            ),
        ],
    )
    def test_from_hex(self, hex_input, expected_hex):
        """Test creating PrivateKey from hex string with various formats."""
        pk = private_key.PrivateKey.from_hex(hex_input)
        assert pk.to_hex == expected_hex

    def test_from_bits(self):
        """Test creating PrivateKey from bit string."""
        # Use a valid private key value (not all 1s which exceeds secp256k1 order)
        bits = "0" + "1" * 255  # Starts with 0 to ensure it's within valid range
        pk = private_key.PrivateKey.from_bits(bits)
        assert pk.to_bits == bits


class TestPrivateKeyValidation:
    """Tests for PrivateKey validation."""

    def test_invalid_length(self):
        """Test that invalid key length raises ValueError."""
        with pytest.raises(ValueError, match="Private key must be exactly 32 bytes"):
            private_key.PrivateKey.from_bytes(b"\x01" * 31)

    @pytest.mark.parametrize(
        "invalid_key_description",
        [
            "zero",  # Zero key
            "equal_to_N",  # Equal to N
            "greater_than_N",  # Greater than N
            "much_greater_than_N",  # Much greater than N
        ],
    )
    def test_out_of_range(self, invalid_key_description):
        """Test that private keys outside valid range raise ValueError."""
        if invalid_key_description == "zero":
            invalid_key = b"\x00" * 32
        elif invalid_key_description == "equal_to_N":
            invalid_key = (secp256k1_curve.SECP256K1_ORDER).to_bytes(
                32, byteorder="big"
            )
        elif invalid_key_description == "greater_than_N":
            invalid_key = (secp256k1_curve.SECP256K1_ORDER + 1).to_bytes(
                32, byteorder="big"
            )
        elif invalid_key_description == "much_greater_than_N":
            invalid_key = (secp256k1_curve.SECP256K1_ORDER + 1000).to_bytes(
                32, byteorder="big"
            )

        with pytest.raises(
            ValueError, match="Private key is out of valid secp256k1 range"
        ):
            private_key.PrivateKey.from_bytes(invalid_key)


class TestPrivateKeyProperties:
    """Tests for PrivateKey properties."""

    def test_all_properties(self):
        """Test all PrivateKey properties."""
        hex_str = "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        pk = private_key.PrivateKey.from_hex(hex_str)

        # Test to_bytes
        assert isinstance(pk.to_bytes, bytes)
        assert len(pk.to_bytes) == 32

        # Test to_int
        assert isinstance(pk.to_int, int)
        assert pk.to_int > 0

        # Test to_hex
        assert isinstance(pk.to_hex, str)
        assert len(pk.to_hex) == 64
        assert pk.to_hex == hex_str

        # Test to_bits
        assert isinstance(pk.to_bits, str)
        assert len(pk.to_bits) == 256
        assert all(c in "01" for c in pk.to_bits)

    def test_immutable(self):
        """Test that PrivateKey is immutable (frozen dataclass)."""
        pk = private_key.PrivateKey.from_hex(
            "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        )
        with pytest.raises(Exception):  # FrozenInstanceError
            pk._key_bytes = b"\x00" * 32


class TestPrivateKeyHelpers:
    """Tests for helper functions."""

    @pytest.mark.parametrize(
        "invalid_hex,error_match",
        [
            ("xyz123", "Hex string contains non-hex characters"),
            ("hello", "Hex string contains non-hex characters"),
            ("12 34 gg", "Hex string contains non-hex characters"),
            ("a" * 65, "Hex string is longer than 32 bytes"),
            ("f" * 70, "Hex string is longer than 32 bytes"),
        ],
    )
    def test_normalize_hex_invalid(self, invalid_hex, error_match):
        """Test that invalid hex strings raise ValueError."""
        with pytest.raises(ValueError, match=error_match):
            private_key._normalize_hex(invalid_hex)

    @pytest.mark.parametrize(
        "invalid_bits,error_match",
        [
            ("", "Bit string is empty"),
            ("   ", "Bit string is empty"),
            ("10102", "Bit string contains non-bit characters"),
            ("abc", "Bit string contains non-bit characters"),
            ("1" * 257, "Bit string is longer than 256 bits"),
            ("0" * 300, "Bit string is longer than 256 bits"),
        ],
    )
    def test_normalize_bits_invalid(self, invalid_bits, error_match):
        """Test that invalid bit strings raise ValueError."""
        with pytest.raises(ValueError, match=error_match):
            private_key._normalize_bits(invalid_bits)


class TestPrivateKeyConversions:
    """Tests for format conversions."""

    def test_roundtrip_conversions(self):
        """Test roundtrip conversions between different formats."""
        original_hex = (
            "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        )

        # Create from hex
        pk1 = private_key.PrivateKey.from_hex(original_hex)

        # Convert to int and back
        pk2 = private_key.PrivateKey.from_int(pk1.to_int)
        assert pk2.to_hex == original_hex

        # Convert to bytes and back
        pk3 = private_key.PrivateKey.from_bytes(pk1.to_bytes)
        assert pk3.to_hex == original_hex

        # Convert to bits and back
        pk4 = private_key.PrivateKey.from_bits(pk1.to_bits)
        assert pk4.to_hex == original_hex

    def test_wif_uncompressed_roundtrip(self):
        """Test WIF uncompressed format roundtrip conversion."""
        original_hex = (
            "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        )

        # Create from hex
        pk1 = private_key.PrivateKey.from_hex(original_hex)
        wif_uncompressed = pk1.to_wif

        # Create from WIF and verify
        pk2 = private_key.PrivateKey.from_wif(wif_uncompressed)
        assert pk2.to_hex == original_hex
        assert pk2.to_wif == wif_uncompressed

    def test_wif_compressed_roundtrip(self):
        """Test WIF compressed format roundtrip conversion."""
        original_hex = (
            "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        )

        # Create from hex
        pk1 = private_key.PrivateKey.from_hex(original_hex)
        wif_compressed = pk1.to_wif_compressed

        # Create from WIF and verify
        pk2 = private_key.PrivateKey.from_wif(wif_compressed)
        assert pk2.to_hex == original_hex
        assert pk2.to_wif_compressed == wif_compressed

    def test_wif_different_formats(self):
        """Test that uncompressed and compressed WIF produce different strings but same key."""
        original_hex = (
            "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        )

        pk = private_key.PrivateKey.from_hex(original_hex)

        # WIF formats should be different
        assert pk.to_wif != pk.to_wif_compressed

        # But both should have the same length characteristics
        assert len(pk.to_wif) == 51  # Uncompressed WIF is typically 51 chars
        # Compressed WIF is typically 52 chars
        assert len(pk.to_wif_compressed) == 52

    def test_wif_invalid_checksum(self):
        """Test that invalid WIF checksum raises ValueError."""
        # Take a valid WIF and corrupt the last character (checksum)
        valid_wif = "5Jn1i1SnCitA5jQCV116A93CL7BkM3b3Db8uhKt4mcPMw42zirU"
        # Change last character to corrupt the checksum
        invalid_wif = f"{valid_wif[:-1]}1"

        with pytest.raises(ValueError, match="Invalid WIF: checksum mismatch"):
            private_key.PrivateKey.from_wif(invalid_wif)
