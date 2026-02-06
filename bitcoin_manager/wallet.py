from . import address
from . import private_key
from . import public_key


class Wallet:
    """Represents a Bitcoin wallet with a private key, public key, and Taproot address."""

    def __init__(self) -> None:
        raise TypeError("Use Wallet.from_private_key for construction")

    @classmethod
    def _from_private_key(cls, priv_key: private_key.PrivateKey) -> "Wallet":
        instance = object.__new__(cls)
        instance._init_from_private_key(priv_key)
        return instance

    def _init_from_private_key(self, priv_key: private_key.PrivateKey) -> None:
        self._private_key = priv_key
        self._public_key_cache: public_key.PublicKey | None = None
        self._address_cache: address.TaprootAddress | None = None

    @classmethod
    def from_private_key(cls, priv_key: private_key.PrivateKey) -> "Wallet":
        """Create a wallet from a PrivateKey instance."""
        return cls._from_private_key(priv_key)

    @property
    def private_key(self) -> private_key.PrivateKey:
        """Return the private key."""
        return self._private_key

    @property
    def public_key(self) -> public_key.PublicKey:
        """Return the public key."""
        if self._public_key_cache is None:
            self._public_key_cache = public_key.PublicKey.from_private_key(
                self._private_key
            )
        return self._public_key_cache

    @property
    def address(self) -> address.TaprootAddress:
        """Return the Taproot address object."""
        if self._address_cache is None:
            self._address_cache = address.TaprootAddress.from_public_key(
                self.public_key
            )
        return self._address_cache

    def __str__(self) -> str:
        """Return a user-friendly string representation of the wallet."""
        return (
            f"Bitcoin Wallet\n"
            f"==============\n"
            f"Private Key (WIF): {self._private_key.to_wif_compressed}\n"
            f"Public Key (SEC1): {self.public_key.to_sec1_compressed_raw_bytes.hex()}\n"
            f"Address (Taproot): {self.address.address}"
        )
