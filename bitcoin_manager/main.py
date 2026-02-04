from . import private_key as pv
from . import address


def main():
    # Open and read the private key file
    with open("private_key.txt", "r") as f:
        private_key_bits = f.read().strip()

    # Create a private key object from the binary string
    private_key = pv.PrivateKey.from_bits(private_key_bits)
    print(f"Private key bits: {private_key.to_bits}")

    # Generate the taproot address
    taproot_address = address.get_taproot_address(private_key.to_bytes)
    print(f"Address: {taproot_address}")


if __name__ == "__main__":
    main()
