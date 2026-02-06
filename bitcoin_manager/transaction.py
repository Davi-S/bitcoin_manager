import secrets
import typing as t

from . import address
from . import crypto_utils
from . import private_key
from .crypto_utils import secp256k1_curve
from . import wallet as wallet_module


class Prevout:
    """Represents the details of a spent output (UTXO)."""

    def __init__(self, amount: int, script_pubkey: bytes) -> None:
        if amount < 0:
            raise ValueError("amount must be non-negative")
        self._amount = amount
        self._script_pubkey = script_pubkey

    @property
    def amount(self) -> int:
        return self._amount

    @property
    def script_pubkey(self) -> bytes:
        return self._script_pubkey


class TxInput:
    """Represents a Bitcoin transaction input."""

    def __init__(
        self,
        txid: bytes,
        vout: int,
        script_sig: bytes = b"",
        sequence: int = 0xFFFFFFFF,
    ) -> None:
        if len(txid) != 32:
            raise ValueError("txid must be 32 bytes")
        if vout < 0:
            raise ValueError("vout must be non-negative")
        if sequence < 0 or sequence > 0xFFFFFFFF:
            raise ValueError("sequence must be a 32-bit unsigned integer")
        self._txid = txid
        self._vout = vout
        self._script_sig = script_sig
        self._sequence = sequence

    @classmethod
    def from_hex(cls, txid_hex: str, vout: int, sequence: int = 0xFFFFFFFF) -> "TxInput":
        cleaned = txid_hex.strip().lower()
        cleaned = cleaned.removeprefix("0x")
        if len(cleaned) != 64:
            raise ValueError("txid hex must be 32 bytes (64 hex chars)")
        return cls(bytes.fromhex(cleaned), vout=vout, sequence=sequence)
    
    @property
    def txid(self) -> bytes:
        return self._txid

    @property
    def vout(self) -> int:
        return self._vout

    @property
    def script_sig(self) -> bytes:
        return self._script_sig

    @property
    def sequence(self) -> int:
        return self._sequence

    def serialize(self) -> bytes:
        return (
            self.txid[::-1]
            + crypto_utils.int_to_le_bytes(self.vout, 4)
            + crypto_utils.encode_varint(len(self.script_sig))
            + self.script_sig
            + crypto_utils.int_to_le_bytes(self.sequence, 4)
        )


class TxOutput:
    """Represents a Bitcoin transaction output."""

    def __init__(self, value: int, script_pubkey: bytes) -> None:
        if value < 0:
            raise ValueError("value must be non-negative")
        self._value = value
        self._script_pubkey = script_pubkey

    @property
    def value(self) -> int:
        return self._value

    @property
    def script_pubkey(self) -> bytes:
        return self._script_pubkey

    def serialize(self) -> bytes:
        return (
            crypto_utils.int_to_le_bytes(self.value, 8)
            + crypto_utils.encode_varint(len(self.script_pubkey))
            + self.script_pubkey
        )


class Transaction:
    """Represents an immutable Bitcoin transaction with inputs, outputs, and witnesses."""

    def __init__(
        self,
        version: int = 2,
        locktime: int = 0,
        inputs: t.Optional[t.Iterable[TxInput]] = None,
        outputs: t.Optional[t.Iterable[TxOutput]] = None,
        witnesses: t.Optional[t.Iterable[t.Iterable[bytes]]] = None,
    ) -> None:
        self._version = version
        self._locktime = locktime
        self._inputs = tuple(inputs) if inputs else tuple()
        self._outputs = tuple(outputs) if outputs else tuple()
        if witnesses is None:
            self._witnesses = tuple(tuple() for _ in self._inputs)
        else:
            self._witnesses = tuple(tuple(w) for w in witnesses)
        if len(self._witnesses) != len(self._inputs):
            raise ValueError("witnesses length must match number of inputs")

    @property
    def inputs(self) -> t.Tuple[TxInput, ...]:
        return tuple(self._inputs)

    @property
    def outputs(self) -> t.Tuple[TxOutput, ...]:
        return tuple(self._outputs)

    @property
    def version(self) -> int:
        return self._version

    @property
    def locktime(self) -> int:
        return self._locktime
    
    @property
    def witnesses(self) -> t.Tuple[t.Tuple[bytes, ...], ...]:
        return tuple(self._witnesses)

    def serialize(self, include_witness: bool = True) -> bytes:
        use_witness = include_witness and any(self._witnesses)
        result = crypto_utils.int_to_le_bytes(self._version, 4)
        if use_witness:
            result += b"\x00\x01"
        result += crypto_utils.encode_varint(len(self._inputs))
        for tx_input in self._inputs:
            result += tx_input.serialize()
        result += crypto_utils.encode_varint(len(self._outputs))
        for tx_output in self._outputs:
            result += tx_output.serialize()
        if use_witness:
            for witness in self._witnesses:
                result += crypto_utils.encode_varint(len(witness))
                for item in witness:
                    result += crypto_utils.encode_varint(len(item)) + item
        result += crypto_utils.int_to_le_bytes(self._locktime, 4)
        return result

    def txid(self) -> bytes:
        """Return the transaction ID (double-SHA256 of non-witness serialization)."""
        return crypto_utils.double_sha256(self.serialize(include_witness=False))[::-1]

    def txid_hex(self) -> str:
        return self.txid().hex()


UtxoLookup = t.Callable[[bytes, int], t.Union["Prevout", tuple[int, bytes]]]
InputRef = t.Union["TxInput", t.Tuple[bytes, int], t.Tuple[str, int]]
OutputTarget = t.Union[wallet_module.Wallet, address.TaprootAddress, bytes]


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


def _normalize_input_ref(item: InputRef) -> tuple[bytes, int, int]:
    if isinstance(item, TxInput):
        return item.txid, item.vout, item.sequence
    if not isinstance(item, tuple) or len(item) != 2:
        raise TypeError("input ref must be TxInput or (txid, vout)")
    txid, vout = item
    if not isinstance(vout, int) or vout < 0:
        raise ValueError("vout must be non-negative integer")
    return _normalize_txid(txid), vout, 0xFFFFFFFF


def _resolve_prevout(value: Prevout | tuple[int, bytes]) -> Prevout:
    if isinstance(value, Prevout):
        return value
    if isinstance(value, tuple) and len(value) == 2:
        amount, script_pubkey = value
        return Prevout(amount=amount, script_pubkey=script_pubkey)
    raise TypeError("utxo_lookup must return Prevout or (amount, script_pubkey)")


def _output_target_to_script_pubkey(target: OutputTarget) -> bytes:
    if isinstance(target, wallet_module.Wallet):
        return target.address.to_scriptpubkey()
    if isinstance(target, address.TaprootAddress):
        return target.to_scriptpubkey()
    if isinstance(target, bytes):
        return target
    raise TypeError("output target must be Wallet, TaprootAddress, or script_pubkey")


def _estimate_vbytes(inputs: t.Sequence[TxInput], outputs: t.Sequence[TxOutput]) -> int:
    base_tx = Transaction(inputs=inputs, outputs=outputs)
    base_size = len(base_tx.serialize(include_witness=False))
    if not inputs:
        return base_size
    witness_per_input = 1 + 1 + 64
    witness_size = 2 + (witness_per_input * len(inputs))
    weight = base_size * 4 + witness_size
    return (weight + 3) // 4


class UnsignedTransaction:
    """
    High-level transaction builder for P2TR key-path spends.

    The user specifies inputs (txid/vout), destination, output amount,
    and fee rate. The instance estimates size, fee, and change.
    """

    def __init__(
        self,
        inputs: t.Iterable[InputRef],
        amount_sats: int,
        output: OutputTarget,
        fee_rate_sat_vbyte: int,
        utxo_lookup: UtxoLookup,
        version: int = 2,
        locktime: int = 0,
    ) -> None:
        if amount_sats <= 0:
            raise ValueError("amount_sats must be positive")
        if fee_rate_sat_vbyte <= 0:
            raise ValueError("fee_rate_sat_vbyte must be positive")

        normalized_inputs = tuple(_normalize_input_ref(item) for item in inputs)
        if not normalized_inputs:
            raise ValueError("at least one input is required")

        self._inputs = tuple(
            TxInput(txid=txid, vout=vout, sequence=sequence)
            for txid, vout, sequence in normalized_inputs
        )
        self._output_script_pubkey = _output_target_to_script_pubkey(output)
        self._amount_sats = amount_sats
        self._fee_rate = fee_rate_sat_vbyte
        self._version = version
        self._locktime = locktime

        prevouts: list[Prevout] = []
        for tx_input in self._inputs:
            prevouts.append(_resolve_prevout(utxo_lookup(tx_input.txid, tx_input.vout)))
        self._prevouts = tuple(prevouts)
        self._total_input = sum(prev.amount for prev in self._prevouts)

        self._change_sats = 0
        self._fee_sats = 0
        self._estimated_vbytes = 0
        self._uses_change = False
        self._compute_fee_and_change()

    @property
    def inputs(self) -> t.Tuple[TxInput, ...]:
        return tuple(self._inputs)

    @property
    def output_script_pubkey(self) -> bytes:
        return self._output_script_pubkey

    @property
    def amount_sats(self) -> int:
        return self._amount_sats

    @property
    def output_sats(self) -> int:
        return self._amount_sats

    @property
    def total_input_sats(self) -> int:
        return self._total_input

    @property
    def fee_rate_sat_vbyte(self) -> int:
        return self._fee_rate

    @property
    def estimated_vbytes(self) -> int:
        return self._estimated_vbytes

    @property
    def fee_sats(self) -> int:
        return self._fee_sats

    @property
    def change_sats(self) -> int:
        return self._change_sats

    @property
    def uses_change_output(self) -> bool:
        return self._uses_change

    def _estimate_outputs(self, include_change: bool) -> list[TxOutput]:
        outputs = [
            TxOutput(value=self._amount_sats, script_pubkey=self._output_script_pubkey)
        ]
        if include_change:
            change_script = b"\x51\x20" + (b"\x00" * 32)
            outputs.append(TxOutput(value=0, script_pubkey=change_script))
        return outputs

    def _compute_fee_and_change(self) -> None:
        outputs_no_change = self._estimate_outputs(include_change=False)
        vbytes_no_change = _estimate_vbytes(self._inputs, outputs_no_change)
        fee_no_change = vbytes_no_change * self._fee_rate
        change_no_change = self._total_input - self._amount_sats - fee_no_change

        if change_no_change < 0:
            raise ValueError("insufficient funds for amount and fee")

        self._fee_sats = fee_no_change
        self._change_sats = max(0, change_no_change)
        self._estimated_vbytes = vbytes_no_change
        self._uses_change = change_no_change > 0

        if change_no_change > 0:
            outputs_with_change = self._estimate_outputs(include_change=True)
            vbytes_with_change = _estimate_vbytes(self._inputs, outputs_with_change)
            fee_with_change = vbytes_with_change * self._fee_rate
            change_with_change = self._total_input - self._amount_sats - fee_with_change
            if change_with_change > 0:
                self._fee_sats = fee_with_change
                self._change_sats = change_with_change
                self._estimated_vbytes = vbytes_with_change
                self._uses_change = True
            else:
                self._uses_change = False

    def _build_outputs(self, change_script_pubkey: bytes | None = None) -> list[TxOutput]:
        outputs = [
            TxOutput(value=self._amount_sats, script_pubkey=self._output_script_pubkey)
        ]
        if self._uses_change and self._change_sats > 0:
            if change_script_pubkey is None:
                raise ValueError("change_script_pubkey is required for change output")
            outputs.append(
                TxOutput(value=self._change_sats, script_pubkey=change_script_pubkey)
            )
        return outputs

    def sign(self, wallet: wallet_module.Wallet) -> "SignedTransaction":
        change_script = wallet.address.to_scriptpubkey()
        outputs = self._build_outputs(
            change_script_pubkey=change_script if self._uses_change else None
        )
        unsigned = Transaction(
            version=self._version,
            locktime=self._locktime,
            inputs=self._inputs,
            outputs=outputs,
        )

        witnesses: list[tuple[bytes, ...]] = []
        for idx in range(len(unsigned.inputs)):
            sighash = taproot_sighash(
                tx=unsigned,
                input_index=idx,
                prevouts=self._prevouts,
                hash_type=0x00,
            )
            signature = sign_schnorr(
                priv_key=wallet.private_key,
                msg=sighash,
                merkle_root=b"",
            )
            witnesses.append((signature,))

        signed_tx = Transaction(
            version=unsigned.version,
            locktime=unsigned.locktime,
            inputs=unsigned.inputs,
            outputs=unsigned.outputs,
            witnesses=witnesses,
        )
        return SignedTransaction(
            transaction=signed_tx,
            fee_sats=self._fee_sats,
            change_sats=self._change_sats,
            estimated_vbytes=self._estimated_vbytes,
            total_input_sats=self._total_input,
            output_sats=self._amount_sats,
        )


class SignedTransaction:
    """Wraps a fully signed Transaction with high-level metadata."""

    def __init__(
        self,
        transaction: Transaction,
        fee_sats: int,
        change_sats: int,
        estimated_vbytes: int,
        total_input_sats: int,
        output_sats: int,
    ) -> None:
        self._transaction = transaction
        self._fee_sats = fee_sats
        self._change_sats = change_sats
        self._estimated_vbytes = estimated_vbytes
        self._total_input_sats = total_input_sats
        self._output_sats = output_sats

    @property
    def transaction(self) -> Transaction:
        return self._transaction

    @property
    def fee_sats(self) -> int:
        return self._fee_sats

    @property
    def change_sats(self) -> int:
        return self._change_sats

    @property
    def estimated_vbytes(self) -> int:
        return self._estimated_vbytes

    @property
    def total_input_sats(self) -> int:
        return self._total_input_sats

    @property
    def output_sats(self) -> int:
        return self._output_sats

    def serialize(self, include_witness: bool = True) -> bytes:
        return self._transaction.serialize(include_witness=include_witness)

    def txid(self) -> bytes:
        return self._transaction.txid()

    def txid_hex(self) -> str:
        return self._transaction.txid_hex()


def p2tr_scriptpubkey(x_only_pubkey: bytes) -> bytes:
    """Build a P2TR scriptPubKey from a 32-byte x-only public key."""
    if len(x_only_pubkey) != 32:
        raise ValueError("x_only_pubkey must be 32 bytes")
    return b"\x51\x20" + x_only_pubkey


def sign_schnorr(
    priv_key: private_key.PrivateKey,
    msg: bytes,
    aux_rand: bytes | None = None,
    merkle_root: bytes | None = b"",
) -> bytes:
    """
    Create a BIP340 Schnorr signature for a 32-byte message digest.

    Args:
        priv_key: Private key to sign with.
        msg: 32-byte message digest to sign.
        aux_rand: Optional 32-byte auxiliary randomness.
        merkle_root: Optional Taproot Merkle root (32 bytes). Use b"" for key-path
            spend without script tree. Pass None to disable Taproot tweaking.

    Returns:
        64-byte Schnorr signature (r || s).
    """
    if len(msg) != 32:
        raise ValueError("Message must be 32 bytes")

    if aux_rand is None:
        aux_rand = secrets.token_bytes(32)
    if len(aux_rand) != 32:
        raise ValueError("aux_rand must be 32 bytes")

    if merkle_root is not None and len(merkle_root) not in (0, 32):
        raise ValueError("merkle_root must be empty or 32 bytes")

    d0 = priv_key.to_int
    pub_point = secp256k1_curve.G.multiply(d0)

    if pub_point.y % 2 != 0:
        d0 = secp256k1_curve.SECP256K1_ORDER - d0
        pub_point = secp256k1_curve.G.multiply(d0)

    if merkle_root is not None:
        tweak_int = (
            int.from_bytes(
                crypto_utils.tagged_hash(
                    "TapTweak",
                    pub_point.x.to_bytes(32, byteorder="big") + merkle_root,
                ),
                byteorder="big",
            )
            % secp256k1_curve.SECP256K1_ORDER
        )
        if tweak_int != 0:
            d0 = (d0 + tweak_int) % secp256k1_curve.SECP256K1_ORDER
            if d0 == 0:
                raise ValueError("Tweaked private key is zero")
            pub_point = secp256k1_curve.G.multiply(d0)

    d = (
        secp256k1_curve.SECP256K1_ORDER - d0
        if pub_point.y % 2 != 0
        else d0
    )

    px = pub_point.x.to_bytes(32, byteorder="big")
    d_bytes = d.to_bytes(32, byteorder="big")
    aux_hash = crypto_utils.tagged_hash("BIP0340/aux", aux_rand)
    t_bytes = bytes(a ^ b for a, b in zip(d_bytes, aux_hash))

    k0 = (
        int.from_bytes(
            crypto_utils.tagged_hash("BIP0340/nonce", t_bytes + px + msg),
            byteorder="big",
        )
        % secp256k1_curve.SECP256K1_ORDER
    )
    if k0 == 0:
        raise ValueError("Derived nonce is zero")

    r_point = secp256k1_curve.G.multiply(k0)
    k = (
        secp256k1_curve.SECP256K1_ORDER - k0
        if r_point.y % 2 != 0
        else k0
    )

    rx = r_point.x.to_bytes(32, byteorder="big")
    e = (
        int.from_bytes(
            crypto_utils.tagged_hash("BIP0340/challenge", rx + px + msg),
            byteorder="big",
        )
        % secp256k1_curve.SECP256K1_ORDER
    )

    s = (k + e * d) % secp256k1_curve.SECP256K1_ORDER
    return rx + s.to_bytes(32, byteorder="big")


def taproot_sighash(
    tx: "Transaction",
    input_index: int,
    prevouts: t.Sequence["Prevout"],
    hash_type: int = 0x00,
) -> bytes:
    """
    Compute the BIP341 key-path sighash digest (Taproot).

    Supports SIGHASH_DEFAULT (0x00) and SIGHASH_ALL (0x01) without annex
    or script path spends.
    """
    if hash_type not in (0x00, 0x01):
        raise ValueError("Unsupported hash_type (only 0x00 and 0x01 are supported)")
    if input_index < 0 or input_index >= len(tx.inputs):
        raise IndexError("input_index out of range")
    if len(prevouts) != len(tx.inputs):
        raise ValueError("prevouts length must match number of inputs")

    hash_prevouts = crypto_utils.sha256(
        b"".join(
            inp.txid[::-1] + crypto_utils.int_to_le_bytes(inp.vout, 4)
            for inp in tx.inputs
        )
    )
    hash_amounts = crypto_utils.sha256(
        b"".join(crypto_utils.int_to_le_bytes(prev.amount, 8) for prev in prevouts)
    )
    hash_scriptpubkeys = crypto_utils.sha256(
        b"".join(
            crypto_utils.encode_varint(len(prev.script_pubkey)) + prev.script_pubkey
            for prev in prevouts
        )
    )
    hash_sequences = crypto_utils.sha256(
        b"".join(crypto_utils.int_to_le_bytes(inp.sequence, 4) for inp in tx.inputs)
    )
    hash_outputs = crypto_utils.sha256(b"".join(out.serialize() for out in tx.outputs))

    spend_type = 0x00  # key-path, no annex

    sigmsg = (
        b"\x00"
        + bytes([hash_type])
        + crypto_utils.int_to_le_bytes(tx.version, 4)
        + crypto_utils.int_to_le_bytes(tx.locktime, 4)
        + hash_prevouts
        + hash_amounts
        + hash_scriptpubkeys
        + hash_sequences
        + hash_outputs
        + bytes([spend_type])
        + crypto_utils.int_to_le_bytes(input_index, 4)
    )

    return crypto_utils.tagged_hash("TapSighash", sigmsg)
