"""
Tests for address.py - Bitcoin Taproot address generation
"""

import pytest
import address


@pytest.mark.parametrize(
    "hex_key,expected_address",
    # These are arbitrary private keys with their correct taproot values associated
    [
        (
            "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e",
            "bc1p6f4a6lpe98xh2mqwk7g85uzj3sw5ll0vy3ek3gyfmsmt8h277s9quzppm8",
        ),
        (
            "f80db4ed11dd8e0ea9399cbfcb54c859d7c93de42598f9af37ef63af1dfc3c2f",
            "bc1pwusjvwkjm4hs5v4q5z6em55el5a9ypulnxfx83q0anxhnsagqceqwkd7uf",
        ),
    ],
)
def test_get_taproot_address(hex_key, expected_address):
    """Test Taproot P2TR address generation from private keys."""
    key_bytes = bytes.fromhex(hex_key)
    result_address = address.get_taproot_address(key_bytes)
    assert result_address == expected_address


def test_get_taproot_address_invalid_key_length():
    """Test that invalid key length raises ValueError"""
    with pytest.raises(ValueError, match="Private key out of valid range"):
        address.get_taproot_address(b"\x00" * 31)  # 31 bytes instead of 32


@pytest.mark.parametrize(
    "invalid_key_hex",
    [
        "0000000000000000000000000000000000000000000000000000000000000001",  # 1
        "0000000000000000000000000000000000000000000000000000000000000000",  # 0
    ],
)
def test_get_taproot_address_invalid_key_value(invalid_key_hex):
    """Test that non valid private key raises ValueError"""
    invalid_key = bytes.fromhex(invalid_key_hex)
    with pytest.raises(ValueError, match="Private key out of valid range"):
        address.get_taproot_address(invalid_key * 32)
