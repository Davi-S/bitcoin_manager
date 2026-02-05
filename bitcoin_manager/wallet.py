import dataclasses

from . import address
from . import private_key
from . import public_key


@dataclasses.dataclass(frozen=True)
class Wallet:
    """Represents a Bitcoin wallet with a private key, public key, and Taproot address."""

    _private_key: private_key.PrivateKey
    _public_key: public_key.PublicKey = dataclasses.field(init=False, repr=False)
    _address: str = dataclasses.field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Derive public key from private key
        derived_public_key = public_key.PublicKey.from_private_key(self._private_key)
        
        # Generate Taproot address
        taproot_address = address.get_taproot_address(self._public_key)
        
        # Set the derived fields using object.__setattr__ for frozen dataclass
        object.__setattr__(self, "_public_key", derived_public_key)
        object.__setattr__(self, "_address", taproot_address)

    @classmethod
    def from_private_key(cls, priv_key: private_key.PrivateKey) -> "Wallet":
        """Create a wallet from a PrivateKey instance."""
        return cls(priv_key)

    @property
    def private_key(self) -> private_key.PrivateKey:
        """Return the private key."""
        return self._private_key

    @property
    def public_key(self) -> public_key.PublicKey:
        """Return the public key."""
        return self._public_key

    @property
    def address(self) -> str:
        """Return the Taproot address."""
        return self._address

    def __str__(self) -> str:
        """Return a user-friendly string representation of the wallet."""
        return (
            f"Bitcoin Wallet\n"
            f"==============\n"
            f"Private Key (WIF): {self._private_key.to_wif_compressed}\n"
            f"Public Key (SEC1): {self._public_key.to_sec1_compressed_raw_bytes.hex()}\n"
            f"Address (Taproot): {self._address}"
        )
