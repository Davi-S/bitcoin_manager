import dataclasses
import secrets
import typing as t

from . import crypto
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
        if not isinstance(self.script_pubkey, (bytes, bytearray)):
            raise TypeError("script_pubkey must be bytes")


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
            + crypto.int_to_le_bytes(self.vout, 4)
            + crypto.encode_varint(len(self.script_sig))
            + self.script_sig
            + crypto.int_to_le_bytes(self.sequence, 4)
        )


@dataclasses.dataclass(frozen=True)
class TxOutput:
    """Represents a Bitcoin transaction output."""

    value: int
    script_pubkey: bytes

    def __post_init__(self) -> None:
        if self.value < 0:
            raise ValueError("value must be non-negative")
        if not isinstance(self.script_pubkey, (bytes, bytearray)):
            raise TypeError("script_pubkey must be bytes")

    def serialize(self) -> bytes:
        return (
            crypto.int_to_le_bytes(self.value, 8)
            + crypto.encode_varint(len(self.script_pubkey))
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
        self.version = version
        self.locktime = locktime
        self.inputs = list(inputs) if inputs else []
        self.outputs = list(outputs) if outputs else []
        if witnesses is None:
            self.witnesses = [[] for _ in self.inputs]
        else:
            self.witnesses = [list(w) for w in witnesses]
        if len(self.witnesses) != len(self.inputs):
            raise ValueError("witnesses length must match number of inputs")

    def add_input(self, tx_input: TxInput) -> None:
        self.inputs.append(tx_input)
        self.witnesses.append([])

    def add_output(self, tx_output: TxOutput) -> None:
        self.outputs.append(tx_output)

    def set_witness(self, index: int, stack_items: t.Iterable[bytes]) -> None:
        if index < 0 or index >= len(self.inputs):
            raise IndexError("input index out of range")
        self.witnesses[index] = list(stack_items)

    def serialize(self, include_witness: bool = True) -> bytes:
        use_witness = include_witness and any(self.witnesses)
        result = crypto.int_to_le_bytes(self.version, 4)
        if use_witness:
            result += b"\x00\x01"
        result += crypto.encode_varint(len(self.inputs))
        for tx_input in self.inputs:
            result += tx_input.serialize()
        result += crypto.encode_varint(len(self.outputs))
        for tx_output in self.outputs:
            result += tx_output.serialize()
        if use_witness:
            for witness in self.witnesses:
                result += crypto.encode_varint(len(witness))
                for item in witness:
                    result += crypto.encode_varint(len(item)) + item
        result += crypto.int_to_le_bytes(self.locktime, 4)
        return result

    def txid(self) -> bytes:
        """Return the transaction ID (double-SHA256 of non-witness serialization)."""
        return crypto.double_sha256(self.serialize(include_witness=False))[::-1]

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
) -> bytes:
    """
    Create a BIP340 Schnorr signature for a 32-byte message digest.

    Args:
        priv_key: Private key to sign with.
        msg: 32-byte message digest to sign.
        aux_rand: Optional 32-byte auxiliary randomness.

    Returns:
        64-byte Schnorr signature (r || s).
    """
    if len(msg) != 32:
        raise ValueError("Message must be 32 bytes")

    if aux_rand is None:
        aux_rand = secrets.token_bytes(32)
    if len(aux_rand) != 32:
        raise ValueError("aux_rand must be 32 bytes")

    d0 = priv_key.to_int
    pub_point = secp256k1_curve.G.multiply(d0)
    d = (
        secp256k1_curve.SECP256K1_ORDER - d0
        if pub_point.y % 2 != 0
        else d0
    )

    px = pub_point.x.to_bytes(32, byteorder="big")
    d_bytes = d.to_bytes(32, byteorder="big")
    aux_hash = crypto.tagged_hash("BIP0340/aux", aux_rand)
    t_bytes = bytes(a ^ b for a, b in zip(d_bytes, aux_hash))

    k0 = (
        int.from_bytes(
            crypto.tagged_hash("BIP0340/nonce", t_bytes + px + msg),
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
            crypto.tagged_hash("BIP0340/challenge", rx + px + msg),
            byteorder="big",
        )
        % secp256k1_curve.SECP256K1_ORDER
    )

    s = (k + e * d) % secp256k1_curve.SECP256K1_ORDER
    return rx + s.to_bytes(32, byteorder="big")
