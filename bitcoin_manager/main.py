from . import private_key as pv
from . import address
import random
import pathlib

def main():
    # Open and read the private key file
    # with open("private_key.txt", "r") as f:
    #     private_key_bits = f.read().strip()

    for i in range(20):
        random_bytes = random.randbytes(32)

        # Create a private key object from the binary string
        private_key = pv.PrivateKey.from_bytes(random_bytes)
        print(private_key.to_hex)

        # Generate the taproot address
        taproot_address = address.get_taproot_address(private_key.to_bytes)
        print(taproot_address)

        with open(pathlib.Path(".").joinpath(f"wallet_{i+1}"), "w") as f:
            content = f"{private_key.to_hex}\n{taproot_address}"
            f.write(content)

if __name__ == "__main__":
    main()
