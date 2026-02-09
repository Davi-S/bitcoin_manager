import typing as t
from . import crypto_utils
from . import private_key as pv


DUST_LIMIT_P2TR = 330
SIGHASH_DEFAULT = 0x00


def _normalize_txid(txid: bytes | str) -> bytes:
    if isinstance(txid, bytes):
        if len(txid) != 32:
            raise ValueError("txid must be 32 bytes")
        return txid
    cleaned = str(txid).strip().lower().removeprefix("0x")
    if len(cleaned) != 64:
        raise ValueError("txid hex must be 32 bytes (64 hex chars)")
    # Store txid internally in little-endian order.
    return bytes.fromhex(cleaned)[::-1]


def _normalize_witness(witness: t.Iterable[bytes] | None) -> tuple[bytes, ...]:
    if witness is None:
        return ()
    items: list[bytes] = []
    items.extend(bytes(item) for item in witness)
    return tuple(items)


def _validate_script_pubkey(script_pubkey: bytes) -> None:
    if not script_pubkey:
        raise ValueError("script_pubkey must not be empty")


class TransactionInput:
    """Represents a Bitcoin transaction input with embedded prevout data."""

    def __init__(
        self,
        txid: bytes | str,
        vout: int,
        prevout_value_sats: int,
        prevout_script_pubkey: bytes,
        sequence: int = 0xFFFFFFF0,  # Just bellow the max value
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


class Transaction:
    """Represents an immutable SegWit transaction."""

    VERSION = 2
    MARKER = 0x00
    FLAG = 0x01
    LOCKTIME = 0

    def __init__(
        self,
        inputs: t.Iterable[TransactionInput],
        outputs: t.Iterable[TransactionOutput],
        fee_sats: int,
        version: int = VERSION,
        marker: int = MARKER,
        flag: int = FLAG,
        locktime: int = LOCKTIME
    ) -> None:
        """Initialize a SegWit transaction and compute change/fees.

        Change is computed as total_in - total_out - fee_sats. If the change is
        at least the dust limit, a change output is added to the first input's
        prevout_script_pubkey; otherwise change is dropped to zero. The effective
        fee is total_in - total_out after outputs (including any change output)
        are finalized.
        """
        # Validate inputs
        if fee_sats < 0:
            raise ValueError("fee_sats must be a non-negative integer")
        inputs_list = list(inputs)
        outputs_list = list(outputs)
        if not inputs_list:
            raise ValueError("transaction must have at least one input")
        if not outputs_list:
            raise ValueError("transaction must have at least one output")

        # Calculate change and add to outputs
        change_sats = self._compute_change_sats(inputs_list, outputs_list, fee_sats)
        if change_sats >= DUST_LIMIT_P2TR:
            outputs_list.append(
                TransactionOutput(
                    value_sats=change_sats,
                    script_pubkey=inputs_list[0].prevout_script_pubkey,
                )
            )
        else:
            change_sats = 0

        # Save info
        self._inputs = tuple(inputs_list)
        self._outputs = tuple(outputs_list)
        self._version = version
        self._marker = marker
        self._flag = flag
        self._locktime = locktime
        self._change_sats_cache: int | None = None
        self._fee_sats_cache: int | None = None
        self._to_hex_cache: str | None = None
        self._txid_hex_cache: str | None = None

    def _compute_change_sats(
        self,
        inputs: list[TransactionInput],
        outputs: list[TransactionOutput],
        fee_sats: int,
    ) -> int:
        total_in = sum(txin.prevout_value_sats for txin in inputs)
        total_out = sum(txout.value_sats for txout in outputs)
        change = total_in - total_out - fee_sats
        if change < 0:
            raise ValueError("insufficient input amount for outputs and fee")
        return change

    def _serialize_inputs(self) -> bytes:
        # sourcery skip: merge-list-appends-into-extend
        parts: list[bytes] = [crypto_utils.encode_varint(len(self.inputs))]
        for txin in self.inputs:
            parts.append(txin.txid)
            parts.append(crypto_utils.int_to_le_bytes(txin.vout, 4))
            parts.append(b"\x00")
            parts.append(crypto_utils.int_to_le_bytes(txin.sequence, 4))
        return b"".join(parts)

    def _serialize_outputs(self) -> bytes:
        # sourcery skip: merge-list-appends-into-extend
        parts: list[bytes] = [crypto_utils.encode_varint(len(self.outputs))]
        for txout in self.outputs:
            parts.append(crypto_utils.int_to_le_bytes(txout.value_sats, 8))
            parts.append(crypto_utils.encode_varint(len(txout.script_pubkey)))
            parts.append(txout.script_pubkey)
        return b"".join(parts)

    def _serialize_witnesses(self) -> bytes:
        # sourcery skip: merge-list-appends-into-extend
        parts: list[bytes] = []
        for txin in self.inputs:
            parts.append(crypto_utils.encode_varint(len(txin.witness)))
            for item in txin.witness:
                parts.append(crypto_utils.encode_varint(len(item)))
                parts.append(item)
        return b"".join(parts)

    def _serialize_legacy(self) -> bytes:
        return b"".join(
            [
                crypto_utils.int_to_le_bytes(self.VERSION, 4),
                self._serialize_inputs(),
                self._serialize_outputs(),
                crypto_utils.int_to_le_bytes(self.LOCKTIME, 4),
            ]
        )

    def _serialize_segwit(self) -> bytes:
        return b"".join(
            [
                crypto_utils.int_to_le_bytes(self.VERSION, 4),
                bytes([self.MARKER, self.FLAG]),
                self._serialize_inputs(),
                self._serialize_outputs(),
                self._serialize_witnesses(),
                crypto_utils.int_to_le_bytes(self.LOCKTIME, 4),
            ]
        )

    @property
    def to_hex(self) -> str:
        if self._to_hex_cache is None:
            self._to_hex_cache = self._serialize_segwit().hex()
        return self._to_hex_cache

    @property
    def txid_hex(self) -> str:
        if self._txid_hex_cache is None:
            digest = crypto_utils.double_sha256(self._serialize_legacy())
            self._txid_hex_cache = digest[::-1].hex()
        return self._txid_hex_cache

    @property
    def change_sats(self) -> int:
        if self._change_sats_cache is None:
            change_scripts = {txin.prevout_script_pubkey for txin in self.inputs}
            self._change_sats_cache = sum(
                txout.value_sats
                for txout in self.outputs
                if txout.script_pubkey in change_scripts
            )
        return self._change_sats_cache

    @property
    def fee_sats(self) -> int:
        if self._fee_sats_cache is None:
            total_in = sum(txin.prevout_value_sats for txin in self.inputs)
            total_out = sum(txout.value_sats for txout in self.outputs)
            fee = total_in - total_out
            if fee < 0:
                raise ValueError("insufficient input amount for outputs")
            self._fee_sats_cache = fee
        return self._fee_sats_cache

    @property
    def inputs(self) -> tuple[TransactionInput, ...]:
        return tuple(self._inputs)

    @property
    def outputs(self) -> tuple[TransactionOutput, ...]:
        return tuple(self._outputs)

    @property
    def version(self) -> int: 
        return self._version
    
    @property
    def marker(self) -> int:
        return self._marker

    @property
    def flag(self) -> int:
        return self._flag
    
    @property
    def locktime(self) -> int:
        return self._locktime

class TaprootSigner:
    """Sign Taproot key-path inputs."""

    @staticmethod
    def _taproot_tweak_seckey(
        priv_key: pv.PrivateKey, merkle_root: bytes = b""
    ) -> tuple[int, bytes]:
        if merkle_root not in (b"",) and len(merkle_root) != 32:
            raise ValueError("merkle_root must be 32 bytes or empty")

        n = crypto_utils.SECP256K1_ORDER
        d = priv_key.to_int
        internal_point = crypto_utils.SECP256K1_GENERATOR_POINT.multiply(d)
        if internal_point.y % 2 != 0:
            d = n - d
            internal_point = internal_point.negate()

        internal_pubkey = internal_point.x.to_bytes(32, byteorder="big")
        tweak_hash = crypto_utils.tagged_hash("TapTweak", internal_pubkey + merkle_root)
        tweak = int.from_bytes(tweak_hash, byteorder="big") % n
        tweaked = (d + tweak) % n
        if tweaked == 0:
            raise ValueError("invalid tweaked private key")

        tweaked_point = crypto_utils.SECP256K1_GENERATOR_POINT.multiply(tweaked)
        if tweaked_point.y % 2 != 0:
            tweaked = n - tweaked
            tweaked_point = tweaked_point.negate()

        return tweaked, tweaked_point.x.to_bytes(32, byteorder="big")

    @staticmethod
    def _schnorr_sign(msg32: bytes, seckey_int: int, pubkey_x: bytes) -> bytes:
        if len(msg32) != 32:
            raise ValueError("message must be 32 bytes")
        if len(pubkey_x) != 32:
            raise ValueError("pubkey_x must be 32 bytes")

        n = crypto_utils.SECP256K1_ORDER
        d = seckey_int % n
        if d == 0:
            raise ValueError("invalid private key")

        d_bytes = d.to_bytes(32, byteorder="big")
        aux = b"\x00" * 32
        aux_hash = crypto_utils.tagged_hash("BIP0340/aux", aux)
        t = bytes(a ^ b for a, b in zip(d_bytes, aux_hash))
        k0 = (
            int.from_bytes(
                crypto_utils.tagged_hash("BIP0340/nonce", t + pubkey_x + msg32),
                byteorder="big",
            )
            % n
        )
        if k0 == 0:
            raise ValueError("invalid nonce")

        r_point = crypto_utils.SECP256K1_GENERATOR_POINT.multiply(k0)
        if r_point.y % 2 != 0:
            k0 = n - k0
            r_point = r_point.negate()

        r_bytes = r_point.x.to_bytes(32, byteorder="big")
        e = (
            int.from_bytes(
                crypto_utils.tagged_hash(
                    "BIP0340/challenge", r_bytes + pubkey_x + msg32
                ),
                byteorder="big",
            )
            % n
        )
        s = (k0 + e * d) % n
        return r_bytes + s.to_bytes(32, byteorder="big")

    @staticmethod
    def _taproot_sighash(
        transaction: "Transaction", input_index: int, sighash_type: int
    ) -> bytes:
        if sighash_type != SIGHASH_DEFAULT:
            raise NotImplementedError("only SIGHASH_DEFAULT is supported")
        if input_index < 0 or input_index >= len(transaction.inputs):
            raise IndexError("input_index out of range")

        inputs = transaction.inputs
        outputs = transaction.outputs

        hash_prevouts = crypto_utils.sha256(
            b"".join(
                txin.txid + crypto_utils.int_to_le_bytes(txin.vout, 4)
                for txin in inputs
            )
        )
        hash_amounts = crypto_utils.sha256(
            b"".join(
                crypto_utils.int_to_le_bytes(txin.prevout_value_sats, 8)
                for txin in inputs
            )
        )
        hash_script_pubkeys = crypto_utils.sha256(
            b"".join(
                crypto_utils.encode_varint(len(txin.prevout_script_pubkey))
                + txin.prevout_script_pubkey
                for txin in inputs
            )
        )
        hash_sequences = crypto_utils.sha256(
            b"".join(crypto_utils.int_to_le_bytes(txin.sequence, 4) for txin in inputs)
        )
        hash_outputs = crypto_utils.sha256(
            b"".join(
                crypto_utils.int_to_le_bytes(txout.value_sats, 8)
                + crypto_utils.encode_varint(len(txout.script_pubkey))
                + txout.script_pubkey
                for txout in outputs
            )
        )

        message = b"".join(
            [
                b"\x00",
                bytes([sighash_type]),
                crypto_utils.int_to_le_bytes(transaction.VERSION, 4),
                crypto_utils.int_to_le_bytes(transaction.LOCKTIME, 4),
                hash_prevouts,
                hash_amounts,
                hash_script_pubkeys,
                hash_sequences,
                hash_outputs,
                b"\x00",
                crypto_utils.int_to_le_bytes(input_index, 4),
            ]
        )
        return crypto_utils.tagged_hash("TapSighash", message)

    @staticmethod
    def sign_keypath(
        transaction: Transaction,
        input_index: int,
        priv_key: pv.PrivateKey,
        sighash_type: int = SIGHASH_DEFAULT,
    ) -> Transaction:
        sighash = TaprootSigner._taproot_sighash(transaction, input_index, sighash_type)
        tweaked_key, pubkey_x = TaprootSigner._taproot_tweak_seckey(priv_key)
        signature = TaprootSigner._schnorr_sign(sighash, tweaked_key, pubkey_x)
        if sighash_type != SIGHASH_DEFAULT:
            signature += bytes([sighash_type])

        inputs = list(transaction.inputs)
        inputs[input_index] = inputs[input_index].with_witness([signature])

        return Transaction(
            inputs=inputs,
            outputs=list(transaction.outputs),
            fee_sats=transaction.fee_sats,
        )
