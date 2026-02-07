from . import address
from . import crypto_utils
from . import private_key as pv
from . import transaction as tx
from . import wallet as wlt

# ============================================================================
# TRANSACTION CONFIGURATION
# ============================================================================

# Private key (WIF format)
PRIVATE_KEY_WIF = "KyFiruDqzurHBHs4QcdU9SkAFd9Ad3xaUP7R84AtFU4sJ8a48hyQ"

# Input transaction details
INPUT_TXID = "aaf28ac10058ae51aa390b3a6d4320a70471e53eb6829697a4c979bc77b9cfb8"
INPUT_VOUT = 0 
INPUT_AMOUNT_SAT = 11363

# Output details
DESTINATION_ADDRESS = "bc1p77n8yxsul45wwzwzemzxeyk89hen4w9526pjhy0dfr2xeexm32xs9fm84x"
SEND_AMOUNT_SAT = 5000

# Fee configuration
FEE_SAT = 248

# ============================================================================
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
            script_pubkey=address.TaprootAddress.from_address(DESTINATION_ADDRESS).scriptpubkey
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
        transaction=unsigned_tx,
        input_index=0,
        priv_key=wallet.private_key
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


if __name__ == "__main__":
    main()