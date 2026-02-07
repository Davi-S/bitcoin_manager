import typing as t

_DEFAULT_SEQUENCE = 0xFFFFFFFF
DUST_LIMIT_P2TR = 330


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
    ...
    

class Transaction:
    """Represents an immutable SegWit transaction."""
    ...