from . import address
from . import private_key as pv
from . import transaction as tx
from . import wallet as wlt


# Private key (WIF format)
PRIVATE_KEY_WIF = "KzC1MocBm6hVMgdBceJGunm4FmKcrnvyt75VkBZSjRUmsCZwLunm"

# Input transaction details
INPUT_TXID = "d31365dd5eb907c7618f6cfb12eb330cf0b15ac468ab573051975549c2f77030"
INPUT_VOUT = 0
INPUT_AMOUNT_SAT = 24383

# Fee configuration
FEE_SAT = 373

# Output details
DESTINATION_ADDRESS = "bc1pgwyhkkcpnavptqdp852q22prrlemelr9mv4umaednz85duu38d5q37lzw7"
SEND_AMOUNT_SAT = 24383 - FEE_SAT


def main():
    wallet = wlt.Wallet.from_private_key(pv.PrivateKey.from_wif(PRIVATE_KEY_WIF))

    inputs = [
        tx.TransactionInput(
            txid=INPUT_TXID,
            vout=INPUT_VOUT,
            prevout_value_sats=INPUT_AMOUNT_SAT,
            prevout_script_pubkey=wallet.address.scriptpubkey,
        )
    ]

    outputs = [
        tx.TransactionOutput(
            value_sats=SEND_AMOUNT_SAT,
            script_pubkey=address.TaprootAddress.from_address(
                DESTINATION_ADDRESS
            ).scriptpubkey,
        )
    ]

    unsigned_tx = tx.Transaction(
        inputs=inputs,
        outputs=outputs,
        fee_sats=FEE_SAT,
    )

    print("=" * 80)
    print("UNSIGNED TRANSACTION")
    print("=" * 80)
    print(f"TXID: {unsigned_tx.txid_hex}")
    print(f"To Broadcast: {unsigned_tx.to_hex}")
    print()

    signed_tx = tx.TaprootSigner.sign_keypath(
        transaction=unsigned_tx, input_index=0, priv_key=wallet.private_key
    )

    print("=" * 80)
    print("SIGNED TRANSACTION (Ready to Broadcast)")
    print("=" * 80)
    print(f"TXID: {signed_tx.txid_hex}")
    print(f"To Broadcast: {signed_tx.to_hex}")
    print()

    print("=" * 80)
    print("TRANSACTION DETAILS")
    print("=" * 80)
    print(f"Change Amount: {signed_tx.change_sats} sats")
    print(f"Change Amount: {signed_tx.fee_sats} sats")


if __name__ == "__main__":
    main()
