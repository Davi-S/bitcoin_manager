from . import private_key as pv
from . import wallet as wlt
from . import transaction as tx
from . import crypto_utils
from . import secp256k1_curve  # Added top-level import for the tweak logic

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

# Fee configuration
FEE_RATE_SAT_VBYTE = 4

# Estimated transaction size in vbytes
# For P2TR with 1 input + 1 output: approximately 112-113 vbytes
ESTIMATED_VSIZE = 112

# ============================================================================


def main():
    # 1. Setup Wallet & Keys
    private_key = pv.PrivateKey.from_wif(PRIVATE_KEY_WIF)
    wallet = wlt.Wallet.from_private_key(private_key)

    # 2. Setup Outputs
    dest_script_pubkey = crypto_utils.decode_taproot_address(DESTINATION_ADDRESS)

    # Calculate fee & amounts
    fee_sat = ESTIMATED_VSIZE * FEE_RATE_SAT_VBYTE
    output_amount_sat = INPUT_AMOUNT_SAT - fee_sat

    if output_amount_sat < 0:
        print(f"Error: Fee ({fee_sat} sat) exceeds input amount ({INPUT_AMOUNT_SAT} sat)")
        return

    # 3. Create Transaction Structure
    tx_input = tx.TxInput.from_hex(INPUT_TXID, INPUT_VOUT)
    tx_output = tx.TxOutput(value=output_amount_sat, script_pubkey=dest_script_pubkey)

    transaction = (
        tx.Transaction().with_input(tx_input).with_output(tx_output)
    )

    # Print Unsigned Details
    unsigned_tx_bytes = transaction.serialize(include_witness=False)
    unsigned_tx_hex = unsigned_tx_bytes.hex()

    print("=" * 80)
    print("UNSIGNED TRANSACTION")
    print("=" * 80)
    print(f"Hex: {unsigned_tx_hex}")
    print(f"TXID: {transaction.txid_hex()}")
    print()

    # =========================================================================
    # SIGNING LOGIC (Taproot Key Path Spend)
    # =========================================================================

    # Step A: Derive the Tweaked Public Key (Q)
    # The blockchain locks funds to Q, not P. We must replicate this derivation
    # to create the correct ScriptPubKey for the signature hash.
    
    # 1. Get Internal Key (P)
    internal_pubkey = wallet.public_key.to_x_only_even_y_bytes
    
    # 2. Calculate the Tweak
    #    tweak = hash("TapTweak", P + merkle_root)
    #    merkle_root is empty bytes for a simple Key Path spend.
    merkle_root = b""
    tweak_hash = crypto_utils.tagged_hash("TapTweak", internal_pubkey + merkle_root)
    tweak_int = int.from_bytes(tweak_hash, byteorder="big")

    # 3. Calculate Q = P + tweak*G
    P_point = wallet.public_key.to_point_even_y
    tweak_point = secp256k1_curve.G.multiply(tweak_int)
    Q_point = P_point.add(tweak_point)
    
    # Get the x-only bytes of Q (The Key in the Address)
    output_pubkey_bytes = Q_point.x.to_bytes(32, byteorder="big")

    # Step B: Create the "Prevout" Script
    # This must match the ScriptPubKey on the blockchain: OP_1 <Q>
    prevout_script = tx.p2tr_scriptpubkey(output_pubkey_bytes)
    prevout = tx.Prevout(amount=INPUT_AMOUNT_SAT, script_pubkey=prevout_script)

    # Step C: Calculate the Signature Hash (SigMsg)
    # This commits to the inputs, amounts, and the ScriptPubKey we just built.
    sighash_digest = tx.taproot_sighash(
        tx=transaction,
        input_index=0,
        prevouts=[prevout],
        hash_type=0x00,  # SIGHASH_DEFAULT
    )

    # Step D: Sign with Schnorr
    # The sign_schnorr function automatically handles tweaking the PRIVATE key
    # (d -> d') when we pass merkle_root=b"".
    signature = tx.sign_schnorr(
        priv_key=private_key,
        msg=sighash_digest,
        merkle_root=b"", 
    )

    # Step E: Attach Witness
    transaction = transaction.with_witness(0, [signature])

    # =========================================================================
    # FINAL OUTPUT
    # =========================================================================

    print("=" * 80)
    print("WITNESS DATA (Verify this against Mempool.space Preview)")
    print("=" * 80)
    witness_stack = transaction.witnesses[0]
    for i, item in enumerate(witness_stack):
        print(f"Item {i}: {item.hex()}")
    print()
        
    signed_tx_bytes = transaction.serialize(include_witness=True)
    signed_tx_hex = signed_tx_bytes.hex()

    print("=" * 80)
    print("SIGNED TRANSACTION (Ready to Broadcast)")
    print("=" * 80)
    print(f"Hex: {signed_tx_hex}")
    print(f"TXID: {transaction.txid_hex()}")
    print()

    print("=" * 80)
    print("TRANSACTION DETAILS")
    print("=" * 80)
    print(f"Input Amount: {INPUT_AMOUNT_SAT} sat")
    print(f"Output Amount: {crypto_utils.sat_to_btc(output_amount_sat)} BTC ({output_amount_sat} sat)")
    print(f"Fee: {fee_sat} sat")
    print(f"Destination: {DESTINATION_ADDRESS}")


if __name__ == "__main__":
    main()