"""
Tests for transaction.py - immutable Transaction behavior
"""

import pytest

from bitcoin_manager import crypto_utils
from bitcoin_manager import transaction as tx


def _sample_input_output():
    txid = bytes.fromhex("11" * 32)
    tx_input = tx.TxInput(txid, vout=1)
    tx_output = tx.TxOutput(value=1000, script_pubkey=b"\x51")
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
    assert tx1.witnesses == ((),)


def test_witnesses_length_mismatch():
    tx_input, tx_output = _sample_input_output()
    with pytest.raises(ValueError, match="witnesses length must match number of inputs"):
        tx.Transaction(inputs=[tx_input], outputs=[tx_output], witnesses=[])


def test_returned_collections_are_immutable():
    tx_input, tx_output = _sample_input_output()
    tx1 = tx.Transaction(
        inputs=[tx_input],
        outputs=[tx_output],
        witnesses=[(b"sig",)],
    )

    assert isinstance(tx1.inputs, tuple)
    assert isinstance(tx1.outputs, tuple)
    assert isinstance(tx1.witnesses, tuple)

    with pytest.raises(TypeError):
        tx1.inputs[0] = tx_input

    with pytest.raises(TypeError):
        tx1.outputs[0] = tx_output

    with pytest.raises(TypeError):
        tx1.witnesses[0][0] = b"x"


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

    assert tx_base.serialize(include_witness=False) == expected_unsigned

    tx_signed = tx.Transaction(
        version=tx_base.version,
        locktime=tx_base.locktime,
        inputs=tx_base.inputs,
        outputs=tx_base.outputs,
        witnesses=[(b"\x02\x03",)],
    )
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

    assert tx_signed.serialize(include_witness=True) == expected_signed

    expected_txid = crypto_utils.double_sha256(expected_unsigned)[::-1]
    assert tx_base.txid() == expected_txid
    assert len(tx_base.txid()) == 32
    assert len(tx_base.txid_hex()) == 64


def test_external_lists_do_not_mutate_transaction():
    tx_input, tx_output = _sample_input_output()
    inputs = [tx_input]
    outputs = [tx_output]
    witnesses = [(b"sig",)]

    transaction = tx.Transaction(inputs=inputs, outputs=outputs, witnesses=witnesses)
    inputs.append(tx_input)
    outputs.append(tx_output)
    witnesses.append((b"extra",))

    assert transaction.inputs == (tx_input,)
    assert transaction.outputs == (tx_output,)
    assert transaction.witnesses == ((b"sig",),)
