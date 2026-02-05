from . import private_key as pv
from . import wallet as wlt


def main():
    # Open and read the private key file
    with open("private_key.txt", "r") as f:
        private_key_bits = f.read().strip()

    # Create a private key object from the binary string
    private_key = pv.PrivateKey.from_bits(private_key_bits)
    
    wallet = wlt.Wallet.from_private_key(private_key)
    
    print(wallet)


if __name__ == "__main__":
    main()
