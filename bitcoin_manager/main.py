from private_key import PrivateKey
from address import get_taproot_address


def main():
    # Open and read the private key file
    with open("private_key.txt", "r") as f:
        private_key_bits = f.read().strip()

    # Create a private key object from the binary string
    private_key = PrivateKey.from_bits(private_key_bits)

    # Generate the taproot address
    taproot_address = get_taproot_address(private_key.key_bytes)

    # Print the taproot address
    print(taproot_address)


if __name__ == "__main__":
    main()
