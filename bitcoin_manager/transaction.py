import dataclasses
import secrets
import typing as t

from . import crypto_utils
from . import private_key
from . import secp256k1_curve


@dataclasses.dataclass(frozen=True)
class Prevout:
    """Represents the details of a spent output (UTXO)."""

    amount: int
    script_pubkey: bytes

    def __post_init__(self) -> None:
        if self.amount < 0:
            raise ValueError("amount must be non-negative")


@dataclasses.dataclass(frozen=True)
class TxInput:
    """Represents a Bitcoin transaction input."""

    txid: bytes
    vout: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF

    def __post_init__(self) -> None:
        if len(self.txid) != 32:
            raise ValueError("txid must be 32 bytes")
        if self.vout < 0:
            raise ValueError("vout must be non-negative")
        if self.sequence < 0 or self.sequence > 0xFFFFFFFF:
            raise ValueError("sequence must be a 32-bit unsigned integer")

    @classmethod
    def from_hex(cls, txid_hex: str, vout: int, sequence: int = 0xFFFFFFFF) -> "TxInput":
        cleaned = txid_hex.strip().lower()
        cleaned = cleaned.removeprefix("0x")
        if len(cleaned) != 64:
            raise ValueError("txid hex must be 32 bytes (64 hex chars)")
        return cls(bytes.fromhex(cleaned), vout=vout, sequence=sequence)

    def serialize(self) -> bytes:
        return (
            self.txid[::-1]
            + crypto_utils.int_to_le_bytes(self.vout, 4)
            + crypto_utils.encode_varint(len(self.script_sig))
            + self.script_sig
            + crypto_utils.int_to_le_bytes(self.sequence, 4)
        )


@dataclasses.dataclass(frozen=True)
class TxOutput:
    """Represents a Bitcoin transaction output."""

    value: int
    script_pubkey: bytes

    def __post_init__(self) -> None:
        if self.value < 0:
            raise ValueError("value must be non-negative")

    def serialize(self) -> bytes:
        return (
            crypto_utils.int_to_le_bytes(self.value, 8)
            + crypto_utils.encode_varint(len(self.script_pubkey))
            + self.script_pubkey
        )


class Transaction:
    """Represents a Bitcoin transaction with inputs, outputs, and witnesses."""

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
        self._inputs = list(inputs) if inputs else []
        self._outputs = list(outputs) if outputs else []
        if witnesses is None:
            self._witnesses = [[] for _ in self._inputs]
        else:
            self._witnesses = [list(w) for w in witnesses]
        if len(self._witnesses) != len(self._inputs):
            raise ValueError("witnesses length must match number of inputs")

    def add_input(self, tx_input: TxInput) -> None:
        self._inputs.append(tx_input)
        self._witnesses.append([])

    def add_output(self, tx_output: TxOutput) -> None:
        self._outputs.append(tx_output)

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

    def set_witness(self, index: int, stack_items: t.Iterable[bytes]) -> None:
        if index < 0 or index >= len(self._inputs):
            raise IndexError("input index out of range")
        self._witnesses[index] = list(stack_items)

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
