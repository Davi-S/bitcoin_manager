"""Tests for transaction.py - immutable Transaction behavior."""

import pytest

from bitcoin_manager import crypto_utils
from bitcoin_manager import private_key as pv
from bitcoin_manager import transaction as tx


def _sample_input_output():
    txid = bytes.fromhex("11" * 32)
    prevout_script_pubkey = b"\x51\x20" + (b"\x00" * 32)
    tx_input = tx.TransactionInput(
        txid=txid,
        vout=1,
        prevout_value_sats=5000,
        prevout_script_pubkey=prevout_script_pubkey,
    )
    tx_output = tx.TransactionOutput(value_sats=1000, script_pubkey=b"\x51")
    return tx_input, tx_output


def test_constructor_is_immutable():
    tx_input, tx_output = _sample_input_output()
    tx0 = tx.Transaction()
    tx1 = tx.Transaction(inputs=[tx_input], outputs=[tx_output])

    assert tx0 is not tx1
    assert tx0.inputs == ()
    assert tx0.outputs == ()
    assert tx1.inputs == (tx_input,)
    assert tx1.outputs == (tx_output,)


def test_witness_validation():
    txid = bytes.fromhex("11" * 32)
    prevout_script_pubkey = b"\x51\x20" + (b"\x00" * 32)
    with pytest.raises(TypeError, match="witness items must be bytes"):
        tx.TransactionInput(
            txid=txid,
            vout=0,
            prevout_value_sats=5000,
            prevout_script_pubkey=prevout_script_pubkey,
            witness=[123],
        )


def test_returned_collections_are_immutable():
    tx_input, tx_output = _sample_input_output()
    tx1 = tx.Transaction(inputs=[tx_input], outputs=[tx_output])

    assert isinstance(tx1.inputs, tuple)
    assert isinstance(tx1.outputs, tuple)
    assert isinstance(tx1.inputs[0].witness, tuple)

    with pytest.raises(TypeError):
        tx1.inputs[0] = tx_input

    with pytest.raises(TypeError):
        tx1.outputs[0] = tx_output

    with pytest.raises(TypeError):
        tx1.inputs[0].witness[0] = b"x"


def test_serialization_and_txid():
    tx_input, tx_output = _sample_input_output()
    tx_base = tx.Transaction(inputs=[tx_input], outputs=[tx_output])

    expected_unsigned = (
        crypto_utils.int_to_le_bytes(2, 4)
        + crypto_utils.encode_varint(1)
        + tx_input.serialize()
        + crypto_utils.encode_varint(1)
        + tx_output.serialize()
        + crypto_utils.int_to_le_bytes(0, 4)
    )

    assert tx_base.to_bytes(include_witness=False) == expected_unsigned

    tx_signed = tx_base.with_input_witness(0, [b"\x02\x03"])
    expected_signed = (
        crypto_utils.int_to_le_bytes(2, 4)
        + b"\x00\x01"
        + crypto_utils.encode_varint(1)
        + tx_input.serialize()
        + crypto_utils.encode_varint(1)
        + tx_output.serialize()
        + crypto_utils.encode_varint(1)
        + crypto_utils.encode_varint(2)
        + b"\x02\x03"
        + crypto_utils.int_to_le_bytes(0, 4)
    )

    assert tx_signed.to_bytes(include_witness=True) == expected_signed

    expected_txid = crypto_utils.double_sha256(expected_unsigned)[::-1]
    assert tx_base.txid() == expected_txid
    assert len(tx_base.txid()) == 32
    assert len(tx_base.txid_hex()) == 64


def test_external_lists_do_not_mutate_transaction():
    tx_input, tx_output = _sample_input_output()
    inputs = [tx_input]
    outputs = [tx_output]

    transaction = tx.Transaction(inputs=inputs, outputs=outputs)
    inputs.append(tx_input)
    outputs.append(tx_output)

    assert transaction.inputs == (tx_input,)
    assert transaction.outputs == (tx_output,)


def test_taproot_signer_signature_length():
    tx_input, tx_output = _sample_input_output()
    tx_base = tx.Transaction(inputs=[tx_input], outputs=[tx_output])
    priv_key = pv.PrivateKey.from_int(1)

    signature = tx.TaprootSigner.sign_keypath(
        transaction=tx_base, input_index=0, priv_key=priv_key
    )
    assert len(signature) == 64

    signed_tx = tx_base.with_input_witness(0, [signature])
    assert signed_tx.inputs[0].witness[0] == signature
