"""
Tests for hashing.py - Hashing functions
"""

import pytest
from bitcoin_manager.crypto_utils import hashing


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
        result = hashing.sha256(input_data)
        expected = bytes.fromhex(expected_hex)
        assert result == expected


class TestTaggedHash:
    """Tests for BIP340 tagged hash function."""

    def test_consistency(self):
        """Test BIP340 tagged hash produces consistent output."""
        # Test with known tag and message
        result = hashing.tagged_hash("BIP0340/challenge", b"test")
        # Verify it produces consistent output
        result2 = hashing.tagged_hash("BIP0340/challenge", b"test")
        assert result == result2
        assert len(result) == 32

    def test_different_tags(self):
        """Test that different tags produce different hashes."""
        msg = b"same message"
        hash1 = hashing.tagged_hash("tag1", msg)
        hash2 = hashing.tagged_hash("tag2", msg)
        assert hash1 != hash2
