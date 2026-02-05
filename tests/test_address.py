"""
Tests for address.py - Bitcoin Taproot address generation
"""

import pytest
from bitcoin_manager import address
from bitcoin_manager import private_key
from bitcoin_manager import public_key


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
    priv_key = private_key.PrivateKey.from_bytes(key_bytes)
    pub_key = public_key.PublicKey.from_private_key(priv_key)
    result_address = address.get_taproot_address(pub_key)
    assert result_address == expected_address



