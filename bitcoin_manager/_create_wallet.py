from . import private_key as pv
from . import wallet as wlt
import random


def main():
    print(wlt.Wallet.from_private_key(pv.PrivateKey.from_bytes(random.randbytes(32))))


if __name__ == "__main__":
    main()
