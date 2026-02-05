from . import crypto_utils
from . import secp256k1_curve
from . import public_key


def get_taproot_address(pubkey: public_key.PublicKey) -> str:
    """
    Generate Taproot (P2TR) Bitcoin address from public key.

    This follows BIP340 (Schnorr) and BIP341 (Taproot) specifications.

    Args:
        pubkey: PublicKey object

    Returns:
        Bitcoin Taproot address (starts with 'bc1p')
    """
    # Get the even-Y normalized point for BIP340 compatibility
    public_key_point = pubkey.to_point_even_y

    # The internal public key (x-only, 32 bytes)
    internal_pubkey = pubkey.to_x_only_even_y_bytes

    # Compute taproot tweak
    # For key-path only spending (no script tree), merkle_root is empty
    merkle_root = b""  # Empty for key-path only

    # Compute tweak = tagged_hash("TapTweak", internal_pubkey || merkle_root)
    tweak_hash = crypto_utils.tagged_hash("TapTweak", internal_pubkey + merkle_root)
    tweak_int = int.from_bytes(tweak_hash, byteorder="big")

    # Compute output key Q = P + tweak*G
    tweak_point = secp256k1_curve.G.multiply(tweak_int)

    output_point = public_key_point.add(tweak_point)

    # The output public key (x-only, 32 bytes)
    output_pubkey = output_point.x.to_bytes(32, byteorder="big")

    # Encode as Bech32m address (witness version 1)
    # Convert to 5-bit groups for bech32m
    witver = 1
    witprog = crypto_utils.convertbits(list(output_pubkey), 8, 5)

    return crypto_utils.bech32_encode("bc", [witver] + witprog, "bech32m")
