from . import address
from . import crypto_utils
from . import private_key as pv
from . import transaction as tx
from . import wallet as wlt

# ============================================================================
# TRANSACTION CONFIGURATION
# ============================================================================

# Private key (WIF format)
PRIVATE_KEY_WIF = "L3MGEFczMrbmTARqgF8mxPddk8dxsskp226CwscATPQZAGMXRyS3"

# Input transaction details
INPUT_TXID = "470ede9d9dfb486e8b36dcf8f7478e90fca98f7151e5f7502adb226d2e0879d4"
INPUT_VOUT = 41 
INPUT_AMOUNT_SAT = 14484

# Output details
DESTINATION_ADDRESS = "bc1p6l0kx4fnqavqptlv0zv9n5qnmm6cm2famq2nrxcec7lfc6k00vvs5p0tms"
SEND_AMOUNT_SAT = 10_000

# Fee configuration
FEE_RATE_SAT_VBYTE = 4

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
    
    unsigned_tx = tx.create_transaction(
        inputs=inputs,
        outputs=outputs,
        fee_rate_sat_vbyte=FEE_RATE_SAT_VBYTE,
    )

    print("=" * 80)
    print("UNSIGNED TRANSACTION")
    print("=" * 80)
    print(f"{unsigned_tx.txid_hex}")
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
    print()

    print("=" * 80)
    print("TRANSACTION DETAILS")
    print("=" * 80)
    print(f"Change Amount: {unsigned_tx.change_sats} sats")
    print(f"Fee: {unsigned_tx.fee_sats} sat")


if __name__ == "__main__":
    main()