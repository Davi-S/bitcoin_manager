import crypto


def get_taproot_address(private_key_bytes: bytes) -> str:
    """
    Generate Taproot (P2TR) Bitcoin address from private key.

    This follows BIP340 (Schnorr) and BIP341 (Taproot) specifications.

    Args:
        private_key_bytes: 32-byte private key

    Returns:
        Bitcoin Taproot address (starts with 'bc1p')
    """
    # Convert private key to integer
    private_key_int = int.from_bytes(private_key_bytes, byteorder="big")

    if private_key_int == 0 or private_key_int >= crypto.N:
        raise ValueError("Private key out of valid range")

    # Generate public key point (x, y) on secp256k1
    public_key_point = crypto.point_multiply(private_key_int, (crypto.Gx, crypto.Gy))

    x, y = public_key_point

    # For BIP340, if Y is odd, negate the private key
    # This ensures we always use the even Y coordinate
    if y % 2 != 0:
        private_key_int = crypto.N - private_key_int
        public_key_point = crypto.point_multiply(
            private_key_int, (crypto.Gx, crypto.Gy)
        )
        x, y = public_key_point

    # The internal public key (x-only, 32 bytes)
    internal_pubkey = x.to_bytes(32, byteorder="big")

    # Compute taproot tweak
    # For key-path only spending (no script tree), merkle_root is empty
    merkle_root = b""  # Empty for key-path only

    # Compute tweak = tagged_hash("TapTweak", internal_pubkey || merkle_root)
    tweak_hash = crypto.tagged_hash("TapTweak", internal_pubkey + merkle_root)
    tweak_int = int.from_bytes(tweak_hash, byteorder="big")

    # Compute output key Q = P + tweak*G
    tweak_point = crypto.point_multiply(tweak_int, (crypto.Gx, crypto.Gy))

    output_point = crypto.point_add(public_key_point, tweak_point)

    output_x, output_y = output_point

    # The output public key (x-only, 32 bytes)
    output_pubkey = output_x.to_bytes(32, byteorder="big")

    # Encode as Bech32m address (witness version 1)
    # Convert to 5-bit groups for bech32m
    witver = 1
    witprog = crypto.convertbits(list(output_pubkey), 8, 5)

    # Encode as bech32m (mainnet = "bc")
    address = crypto.bech32_encode("bc", [witver] + witprog, "bech32m")
    return address

