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
# CHECK THIS: Ensure this TXID and VOUT match exactly what you see on the explorer
INPUT_TXID = "470ede9d9dfb486e8b36dcf8f7478e90fca98f7151e5f7502adb226d2e0879d4"
INPUT_VOUT = 41  # 0-based index (e.g., if it's the 42nd output, this is 41)
INPUT_AMOUNT_SAT = 14484

# Output details
DESTINATION_ADDRESS = "bc1p6l0kx4fnqavqptlv0zv9n5qnmm6cm2famq2nrxcec7lfc6k00vvs5p0tms"
SEND_AMOUNT_SAT = 10_000

# Fee configuration
FEE_RATE_SAT_VBYTE = 4

# ============================================================================
def main():
    private_key = pv.PrivateKey.from_wif(PRIVATE_KEY_WIF)
    wallet = wlt.Wallet.from_private_key(private_key)
    destination = address.TaprootAddress.from_address(DESTINATION_ADDRESS)

    tx_inputs = [tx.TransactionInput(
        txid=INPUT_TXID,
        vout=INPUT_VOUT,
        prevout_value_sats=INPUT_AMOUNT_SAT,
        prevout_script_pubkey=wallet.address.scriptpubkey,
    )]
    outputs = [
        tx.TransactionOutput(
            value_sats=SEND_AMOUNT_SAT, script_pubkey=destination.scriptpubkey
        )
    ]
    unsigned_tx = tx.Transaction(
        inputs=tx_inputs,
        outputs=outputs,
        change_address=wallet.address,
        fee_rate_sat_vbyte=FEE_RATE_SAT_VBYTE,
    )

    print("=" * 80)
    print("UNSIGNED TRANSACTION")
    print("=" * 80)
    print(f"Estimated vbytes: {unsigned_tx.estimated_vbytes}")
    print(f"Fee: {unsigned_tx.fee_sats} sat")
    print(f"Change: {unsigned_tx.change_sats} sat")
    print()

    signed_tx = tx.TaprootSigner.sign_keypath(
        transaction=unsigned_tx, input_index=0, priv_key=wallet.private_key
    )
    signed_tx_hex = signed_tx.to_hex(include_witness=True)

    print("=" * 80)
    print("SIGNED TRANSACTION (Ready to Broadcast)")
    print("=" * 80)
    print(f"Hex: {signed_tx_hex}")
    print(f"TXID: {signed_tx.txid_hex()}")
    print()

    print("=" * 80)
    print("TRANSACTION DETAILS")
    print("=" * 80)
    print(f"Input Amount: {INPUT_AMOUNT_SAT} sat")
    print(
        f"Output Amount: {crypto_utils.sat_to_btc(SEND_AMOUNT_SAT)} BTC "
        f"({SEND_AMOUNT_SAT} sat)"
    )
    if unsigned_tx.change_sats and unsigned_tx.change_sats > 0:
        print(
            f"Change Amount: {crypto_utils.sat_to_btc(unsigned_tx.change_sats)} BTC "
            f"({unsigned_tx.change_sats} sat)"
        )
    print(f"Fee: {unsigned_tx.fee_sats} sat")
    print(f"Destination: {DESTINATION_ADDRESS}")


if __name__ == "__main__":
    main()