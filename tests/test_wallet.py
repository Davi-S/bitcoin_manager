"""
Tests for wallet.py - Bitcoin wallet with private key, public key, and address
"""

import pytest
from bitcoin_manager import private_key
from bitcoin_manager import wallet


class TestWalletCreation:
    """Tests for Wallet creation methods."""

    def test_from_private_key(self):
        """Test creating Wallet from PrivateKey."""
        key_bytes = bytes.fromhex(
            "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        )
        priv_key = private_key.PrivateKey.from_bytes(key_bytes)
        w = wallet.Wallet.from_private_key(priv_key)

        assert w.private_key == priv_key
        assert w.public_key is not None
        assert w.address.startswith("bc1p")

    def test_wallet_address_derivation(self):
        """Test that wallet derives correct Taproot address."""
        # Using known test vector from test_address.py
        key_hex = "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        expected_address = (
            "bc1p6f4a6lpe98xh2mqwk7g85uzj3sw5ll0vy3ek3gyfmsmt8h277s9quzppm8"
        )

        priv_key = private_key.PrivateKey.from_hex(key_hex)
        w = wallet.Wallet.from_private_key(priv_key)

        assert w.address == expected_address

    def test_wallet_public_key_derivation(self):
        """Test that wallet derives correct public key from private key."""
        key_bytes = bytes.fromhex(
            "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        )
        priv_key = private_key.PrivateKey.from_bytes(key_bytes)
        w = wallet.Wallet.from_private_key(priv_key)

        # Public key should match what PublicKey.from_private_key would create
        from bitcoin_manager import public_key

        expected_pub_key = public_key.PublicKey.from_private_key(priv_key)

        assert (
            w.public_key.to_x_only_even_y_bytes
            == expected_pub_key.to_x_only_even_y_bytes
        )


class TestWalletProperties:
    """Tests for Wallet property access."""

    def test_wallet_properties_accessible(self):
        """Test that all wallet properties are accessible."""
        priv_key = private_key.PrivateKey.from_hex(
            "7e888e146bcf7d8849ed3d8e1341b3a412172d8c886cf76dcc852900d0c51c3e"
        )
        w = wallet.Wallet.from_private_key(priv_key)

        # All properties should be accessible and non-None
        assert w.private_key is not None
        assert w.public_key is not None
        assert w.address is not None
        assert isinstance(w.address, str)
        assert len(w.address) > 0


class TestWalletMultipleKeys:
    """Tests for creating multiple wallets with different keys."""

    @pytest.mark.parametrize(
        "hex_key,expected_address",
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
    def test_wallet_with_different_keys(self, hex_key, expected_address):
        """Test wallet creation with multiple different private keys."""
        priv_key = private_key.PrivateKey.from_hex(hex_key)
        w = wallet.Wallet.from_private_key(priv_key)

        assert w.address == expected_address
        assert w.private_key.to_hex == hex_key
