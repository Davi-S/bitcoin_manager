import typing as t

from . import crypto_utils
from . import private_key as pv
from . import public_key as pb
from .crypto_utils import secp256k1_curve

_DEFAULT_SEQUENCE = 0xFFFFFFFF
DUST_LIMIT_P2TR = 330
SIGHASH_DEFAULT = 0x00
_DEFAULT_VERSION = 2
_DEFAULT_LOCKTIME = 0
_SEGWIT_MARKER = b"\x00"
_SEGWIT_FLAG = b"\x01"


def _normalize_txid(txid: bytes | str) -> bytes:
    if isinstance(txid, bytes):
        if len(txid) != 32:
            raise ValueError("txid must be 32 bytes")
        return txid
    if not isinstance(txid, str):
        raise TypeError("txid must be bytes or hex string")
    cleaned = txid.strip().lower().removeprefix("0x")
    if len(cleaned) != 64:
        raise ValueError("txid hex must be 32 bytes (64 hex chars)")
    return bytes.fromhex(cleaned)


def _normalize_witness(witness: t.Iterable[bytes] | None) -> tuple[bytes, ...]:
    if witness is None:
        return ()
    items: list[bytes] = []
    for item in witness:
        if isinstance(item, (bytes, bytearray)):
            items.append(bytes(item))
        else:
            raise TypeError("witness items must be bytes")
    return tuple(items)


def _validate_script_pubkey(script_pubkey: bytes) -> None:
    if not isinstance(script_pubkey, (bytes, bytearray)):
        raise TypeError("script_pubkey must be bytes")
    if not script_pubkey:
        raise ValueError("script_pubkey must not be empty")


def _le_u32(value: int) -> bytes:
    return crypto_utils.int_to_le_bytes(value, 4)


def _le_u64(value: int) -> bytes:
    return crypto_utils.int_to_le_bytes(value, 8)


def _varint(value: int) -> bytes:
    return crypto_utils.encode_varint(value)


def _serialize_outpoint(txid: bytes, vout: int) -> bytes:
    return txid[::-1] + _le_u32(vout)


def _serialize_txin(txin: "TransactionInput") -> bytes:
    return (
        _serialize_outpoint(txin.txid, txin.vout)
        + _varint(0)
        + _le_u32(txin.sequence)
    )


def _serialize_txout(txout: "TransactionOutput") -> bytes:
    script = txout.script_pubkey
    return _le_u64(txout.value_sats) + _varint(len(script)) + script


def _serialize_witness_stack(items: t.Iterable[bytes]) -> bytes:
    witness_items = list(items)
    payload = [_varint(len(witness_items))]
    for item in witness_items:
        payload.extend((_varint(len(item)), item))
    return b"".join(payload)


def _txin_base_size() -> int:
    return 32 + 4 + 1 + 4


def _txout_size(txout: "TransactionOutput") -> int:
    return 8 + len(_varint(len(txout.script_pubkey))) + len(txout.script_pubkey)


def _base_tx_size(
    inputs: t.Iterable["TransactionInput"],
    outputs: t.Iterable["TransactionOutput"],
    version: int,
    locktime: int,
) -> int:
    inputs_list = list(inputs)
    outputs_list = list(outputs)
    size = 4
    size += len(_varint(len(inputs_list)))
    size += len(inputs_list) * _txin_base_size()
    size += len(_varint(len(outputs_list)))
    size += sum(_txout_size(out) for out in outputs_list)
    size += 4
    return size


def _estimate_vbytes_taproot_keypath(
    inputs: t.Iterable["TransactionInput"],
    outputs: t.Iterable["TransactionOutput"],
    version: int = _DEFAULT_VERSION,
    locktime: int = _DEFAULT_LOCKTIME,
) -> int:
    inputs_list = list(inputs)
    outputs_list = list(outputs)
    base_size = _base_tx_size(inputs_list, outputs_list, version, locktime)
    witness_size = sum(1 + 1 + 64 for _ in inputs_list)
    total_size = base_size
    if witness_size > 0:
        total_size += 2 + witness_size
    weight = base_size * 4 + (total_size - base_size)
    return (weight + 3) // 4


def _taproot_tagged_hash(tag: str, msg: bytes) -> bytes:
    return crypto_utils.tagged_hash(tag, msg)


def _taproot_tweak_privkey(
    priv_key: pv.PrivateKey, merkle_root: bytes = b""
) -> int:
    if merkle_root not in (b"",) and len(merkle_root) != 32:
        raise ValueError("merkle_root must be 32 bytes or empty")
    pub = pb.PublicKey.from_private_key(priv_key)
    priv_int = priv_key.to_int
    if pub.to_point_raw.y % 2 != 0:
        priv_int = secp256k1_curve.SECP256K1_ORDER - priv_int
    internal_pubkey = pub.to_x_only_even_y_bytes
    tweak = int.from_bytes(
        _taproot_tagged_hash("TapTweak", internal_pubkey + merkle_root), "big"
    )
    tweak = secp256k1_curve.mod_secp256k1_order(tweak)
    tweaked = (priv_int + tweak) % secp256k1_curve.SECP256K1_ORDER
    if tweaked == 0:
        raise ValueError("Invalid tweaked private key")
    return tweaked


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _int_to_bytes32(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _schnorr_sign(msg: bytes, priv_key_int: int, aux_rand: bytes | None = None) -> bytes:
    if len(msg) != 32:
        raise ValueError("Schnorr message must be 32 bytes")
    if not (1 <= priv_key_int < secp256k1_curve.SECP256K1_ORDER):
        raise ValueError("Invalid private key for Schnorr signing")
    if aux_rand is None:
        aux_rand = b"\x00" * 32
    if len(aux_rand) != 32:
        raise ValueError("aux_rand must be 32 bytes")

    d0 = priv_key_int
    p = secp256k1_curve.G.multiply(d0)
    if p.y % 2 != 0:
        d0 = secp256k1_curve.SECP256K1_ORDER - d0
        p = secp256k1_curve.G.multiply(d0)

    t = _xor_bytes(_int_to_bytes32(d0), _taproot_tagged_hash("BIP0340/aux", aux_rand))
    k0 = int.from_bytes(
        _taproot_tagged_hash("BIP0340/nonce", t + _int_to_bytes32(p.x) + msg),
        "big",
    )
    k0 = secp256k1_curve.mod_secp256k1_order(k0)
    if k0 == 0:
        raise ValueError("Invalid Schnorr nonce")

    r_point = secp256k1_curve.G.multiply(k0)
    if r_point.y % 2 != 0:
        k0 = secp256k1_curve.SECP256K1_ORDER - k0
        r_point = secp256k1_curve.G.multiply(k0)

    r = _int_to_bytes32(r_point.x)
    e = int.from_bytes(
        _taproot_tagged_hash("BIP0340/challenge", r + _int_to_bytes32(p.x) + msg),
        "big",
    )
    e = secp256k1_curve.mod_secp256k1_order(e)
    s = (k0 + e * d0) % secp256k1_curve.SECP256K1_ORDER
    return r + _int_to_bytes32(s)


def _taproot_sighash_keypath(
    tx: "Transaction", input_index: int, sighash_type: int = SIGHASH_DEFAULT
) -> bytes:
    if sighash_type != SIGHASH_DEFAULT:
        raise ValueError("Only SIGHASH_DEFAULT (0x00) is supported")
    if input_index < 0 or input_index >= len(tx.inputs):
        raise IndexError("input_index out of range")

    inputs_list = tx.inputs
    outputs_list = tx.outputs

    hash_prevouts = crypto_utils.sha256(
        b"".join(_serialize_outpoint(inp.txid, inp.vout) for inp in inputs_list)
    )
    hash_amounts = crypto_utils.sha256(
        b"".join(_le_u64(inp.prevout_value_sats) for inp in inputs_list)
    )
    hash_scriptpubkeys = crypto_utils.sha256(
        b"".join(
            _varint(len(inp.prevout_script_pubkey)) + inp.prevout_script_pubkey
            for inp in inputs_list
        )
    )
    hash_sequences = crypto_utils.sha256(
        b"".join(_le_u32(inp.sequence) for inp in inputs_list)
    )
    hash_outputs = crypto_utils.sha256(
        b"".join(_serialize_txout(out) for out in outputs_list)
    )

    spend_type = 0
    msg = (
        bytes([sighash_type])
        + _le_u32(tx.version)
        + _le_u32(tx.locktime)
        + hash_prevouts
        + hash_amounts
        + hash_scriptpubkeys
        + hash_sequences
        + hash_outputs
        + bytes([spend_type])
        + _le_u32(input_index)
    )
    return _taproot_tagged_hash("TapSighash", msg)


class TransactionInput:
    """Represents a Bitcoin transaction input with embedded prevout data."""

    def __init__(
        self,
        txid: bytes | str,
        vout: int,
        prevout_value_sats: int,
        prevout_script_pubkey: bytes,
        sequence: int = _DEFAULT_SEQUENCE,
        witness: t.Iterable[bytes] | None = None,
    ) -> None:
        self._txid = _normalize_txid(txid)
        if vout < 0:
            raise ValueError("vout must be a non-negative integer")
        if prevout_value_sats < 0:
            raise ValueError("prevout_value_sats must be non-negative")
        _validate_script_pubkey(prevout_script_pubkey)
        if sequence < 0 or sequence > 0xFFFFFFFF:
            raise ValueError("sequence must be a 32-bit unsigned integer")
        self._vout = vout
        self._prevout_value_sats = prevout_value_sats
        self._prevout_script_pubkey = bytes(prevout_script_pubkey)
        self._sequence = sequence
        self._witness = _normalize_witness(witness)

    @property
    def txid(self) -> bytes:
        return self._txid

    @property
    def vout(self) -> int:
        return self._vout

    @property
    def prevout_value_sats(self) -> int:
        return self._prevout_value_sats

    @property
    def prevout_script_pubkey(self) -> bytes:
        return self._prevout_script_pubkey

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def witness(self) -> tuple[bytes, ...]:
        return tuple(self._witness)

    @property
    def has_witness(self) -> bool:
        return len(self._witness) > 0

    def with_witness(self, witness: t.Iterable[bytes] | None) -> "TransactionInput":
        return TransactionInput(
            txid=self._txid,
            vout=self._vout,
            prevout_value_sats=self._prevout_value_sats,
            prevout_script_pubkey=self._prevout_script_pubkey,
            sequence=self._sequence,
            witness=witness,
        )


class TransactionOutput:
    """Represents a Bitcoin transaction output."""

    def __init__(self, value_sats: int, script_pubkey: bytes) -> None:
        if value_sats < 0:
            raise ValueError("value_sats must be non-negative")
        _validate_script_pubkey(script_pubkey)
        self._value_sats = value_sats
        self._script_pubkey = bytes(script_pubkey)

    @property
    def value_sats(self) -> int:
        return self._value_sats

    @property
    def script_pubkey(self) -> bytes:
        return self._script_pubkey


def create_transaction(
    inputs: t.Iterable[TransactionInput], 
    outputs: t.Iterable[TransactionOutput],
    fee_rate_sat_vbyte: int
) -> "Transaction":
    inputs_list = list(inputs)
    outputs_list = list(outputs)
    if not inputs_list:
        raise ValueError("At least one input is required")
    if not outputs_list:
        raise ValueError("At least one output is required")
    if fee_rate_sat_vbyte < 0:
        raise ValueError("fee_rate_sat_vbyte must be non-negative")
    for out in outputs_list:
        if out.value_sats <= 0:
            raise ValueError("Outputs must have positive value")

    total_in = sum(inp.prevout_value_sats for inp in inputs_list)
    total_out = sum(out.value_sats for out in outputs_list)
    if total_in < total_out:
        raise ValueError("Total inputs must be >= total outputs")

    vbytes_no_change = _estimate_vbytes_taproot_keypath(inputs_list, outputs_list)
    fee_no_change = vbytes_no_change * fee_rate_sat_vbyte
    leftover = total_in - total_out - fee_no_change
    change_sats = 0
    fee_sats = fee_no_change

    if leftover >= DUST_LIMIT_P2TR:
        change_output = TransactionOutput(
            value_sats=leftover,
            script_pubkey=inputs_list[0].prevout_script_pubkey,
        )
        outputs_with_change = outputs_list + [change_output]
        vbytes_with_change = _estimate_vbytes_taproot_keypath(
            inputs_list, outputs_with_change
        )
        fee_with_change = vbytes_with_change * fee_rate_sat_vbyte
        change_value = total_in - total_out - fee_with_change
        if change_value < 0:
            raise ValueError("Insufficient funds for fee")
        if change_value >= DUST_LIMIT_P2TR:
            change_sats = change_value
            fee_sats = fee_with_change
            final_change_output = TransactionOutput(
                value_sats=change_value, # Use the calculated value, not 'leftover'
                script_pubkey=inputs_list[0].prevout_script_pubkey,
            )
            outputs_list += [final_change_output]
        else:
            fee_sats = total_in - total_out

    return Transaction(
        inputs=inputs_list,
        outputs=outputs_list,
        fee_rate_sat_vbyte=fee_rate_sat_vbyte,
        fee_sats=fee_sats,
        change_sats=change_sats,
    )
    

class Transaction:
    """Represents an immutable SegWit transaction."""
    def __init__(
        self,
        inputs: t.Iterable[TransactionInput],
        outputs: t.Iterable[TransactionOutput],
        fee_rate_sat_vbyte: int,
        version: int = _DEFAULT_VERSION,
        locktime: int = _DEFAULT_LOCKTIME,
        fee_sats: int | None = None,
        change_sats: int | None = None,
    ) -> None:
        inputs_list = list(inputs)
        outputs_list = list(outputs)
        self._inputs = tuple(inputs_list)
        self._outputs = tuple(outputs_list)
        self._fee_rate_sat_vbyte = fee_rate_sat_vbyte
        self._version = version
        self._locktime = locktime
        self._total_in_sats = sum(inp.prevout_value_sats for inp in self._inputs)
        self._total_out_sats = sum(out.value_sats for out in self._outputs)
        computed_fee = self._total_in_sats - self._total_out_sats
        if fee_sats is None:
            fee_sats = computed_fee
        if change_sats is None:
            change_sats = 0
        self._fee_sats = fee_sats
        self._change_sats = change_sats

    @property
    def inputs(self) -> tuple[TransactionInput, ...]:
        return tuple(self._inputs)

    @property
    def outputs(self) -> tuple[TransactionOutput, ...]:
        return tuple(self._outputs)

    @property
    def fee_rate_sat_vbyte(self) -> int:
        return self._fee_rate_sat_vbyte

    @property
    def version(self) -> int:
        return self._version

    @property
    def locktime(self) -> int:
        return self._locktime

    @property
    def total_in_sats(self) -> int:
        return self._total_in_sats

    @property
    def total_out_sats(self) -> int:
        return self._total_out_sats

    @property
    def fee_sats(self) -> int:
        return self._fee_sats

    @property
    def change_sats(self) -> int:
        return self._change_sats

    @property
    def total_sent_sats(self) -> int:
        total = self._total_out_sats - self._change_sats
        return max(total, 0)

    @property
    def has_witness(self) -> bool:
        return any(inp.has_witness for inp in self._inputs)

    @property
    def serialized_no_witness(self) -> bytes:
        return self._serialize(include_witness=False)

    @property
    def serialized(self) -> bytes:
        return self._serialize(include_witness=self.has_witness)

    @property
    def raw_hex(self) -> str:
        """Return the raw transaction hex ready for broadcast."""
        return self.serialized.hex()

    def _serialize(self, include_witness: bool) -> bytes:
        inputs_payload = b"".join(_serialize_txin(inp) for inp in self._inputs)
        outputs_payload = b"".join(_serialize_txout(out) for out in self._outputs)
        payload = [
            _le_u32(self._version),
            _varint(len(self._inputs)),
            inputs_payload,
            _varint(len(self._outputs)),
            outputs_payload,
        ]
        if include_witness:
            witness_payload = b"".join(
                _serialize_witness_stack(inp.witness) for inp in self._inputs
            )
            return (
                _le_u32(self._version)
                + _SEGWIT_MARKER
                + _SEGWIT_FLAG
                + _varint(len(self._inputs))
                + inputs_payload
                + _varint(len(self._outputs))
                + outputs_payload
                + witness_payload
                + _le_u32(self._locktime)
            )
        return b"".join(payload) + _le_u32(self._locktime)

    @property
    def txid(self) -> bytes:
        return crypto_utils.double_sha256(self.serialized_no_witness)[::-1]

    @property
    def txid_hex(self) -> str:
        return self.txid.hex()

    @property
    def wtxid(self) -> bytes:
        return crypto_utils.double_sha256(self.serialized)[::-1]

    @property
    def wtxid_hex(self) -> str:
        return self.wtxid.hex()

    @property
    def base_size(self) -> int:
        return len(self.serialized_no_witness)

    @property
    def total_size(self) -> int:
        return len(self.serialized)

    @property
    def weight(self) -> int:
        base_size = self.base_size
        total_size = self.total_size
        return base_size * 4 + (total_size - base_size)

    @property
    def vbytes(self) -> int:
        return (self.weight + 3) // 4

class TaprootSigner:
    """Sign Taproot key-path inputs."""

    @staticmethod
    def sign_keypath(
        transaction: Transaction,
        input_index: int,
        priv_key: pv.PrivateKey,
        sighash_type: int = SIGHASH_DEFAULT,
    ) -> Transaction:
        sighash = _taproot_sighash_keypath(transaction, input_index, sighash_type)
        tweaked = _taproot_tweak_privkey(priv_key)
        signature = _schnorr_sign(sighash, tweaked)
        if input_index < 0 or input_index >= len(transaction.inputs):
            raise IndexError("input_index out of range")
        inputs_list = list(transaction.inputs)
        inputs_list[input_index] = inputs_list[input_index].with_witness([signature])
        return Transaction(
            inputs=inputs_list,
            outputs=transaction.outputs,
            fee_rate_sat_vbyte=transaction.fee_rate_sat_vbyte,
            version=transaction.version,
            locktime=transaction.locktime,
            fee_sats=transaction.fee_sats,
            change_sats=transaction.change_sats,
        )