from . import address
from . import private_key as pv
from . import wallet as wlt
from . import transaction as tx
from . import crypto_utils

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

    def utxo_lookup(txid: bytes, vout: int) -> tx.Prevout:
        if txid != bytes.fromhex(INPUT_TXID) or vout != INPUT_VOUT:
            raise KeyError("Unknown input")
        script_pubkey = wallet.address.to_scriptpubkey()
        return tx.Prevout(amount=INPUT_AMOUNT_SAT, script_pubkey=script_pubkey)

    unsigned_tx = tx.UnsignedTransaction(
        inputs=[(INPUT_TXID, INPUT_VOUT)],
        amount_sats=SEND_AMOUNT_SAT,
        output=destination,
        fee_rate_sat_vbyte=FEE_RATE_SAT_VBYTE,
        utxo_lookup=utxo_lookup,
    )

    print("=" * 80)
    print("UNSIGNED TRANSACTION")
    print("=" * 80)
    print(f"Estimated vbytes: {unsigned_tx.estimated_vbytes}")
    print(f"Fee: {unsigned_tx.fee_sats} sat")
    print(f"Change: {unsigned_tx.change_sats} sat")
    print()

    signed_tx = unsigned_tx.sign(wallet)
    signed_tx_hex = signed_tx.serialize(include_witness=True).hex()

    print("=" * 80)
    print("SIGNED TRANSACTION (Ready to Broadcast)")
    print("=" * 80)
    print(f"Hex: {signed_tx_hex}")
    print(f"TXID: {signed_tx.txid_hex()}")
    print()

    print("=" * 80)
    print("TRANSACTION DETAILS")
    print("=" * 80)
    print(f"Input Amount: {unsigned_tx.total_input_sats} sat")
    print(
        f"Output Amount: {crypto_utils.sat_to_btc(unsigned_tx.output_sats)} BTC "
        f"({unsigned_tx.output_sats} sat)"
    )
    if unsigned_tx.change_sats > 0:
        print(
            f"Change Amount: {crypto_utils.sat_to_btc(unsigned_tx.change_sats)} BTC "
            f"({unsigned_tx.change_sats} sat)"
        )
    print(f"Fee: {unsigned_tx.fee_sats} sat")
    print(f"Destination: {DESTINATION_ADDRESS}")


if __name__ == "__main__":
    main()