import secrets
import typing as t

from . import address
from . import crypto_utils
from . import private_key
from .crypto_utils import secp256k1_curve


_DEFAULT_SEQUENCE = 0xFFFFFFFF


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
		return tuple()
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
	if len(script_pubkey) == 0:
		raise ValueError("script_pubkey must not be empty")


def _scriptpubkey_from_target(target: address.TaprootAddress | bytes) -> bytes:
	if isinstance(target, address.TaprootAddress):
		return target.scriptpubkey
	if isinstance(target, (bytes, bytearray)):
		_validate_script_pubkey(target)
		return bytes(target)
	raise TypeError("target must be TaprootAddress or script_pubkey bytes")


def _estimate_vbytes(inputs: t.Sequence["TransactionInput"], outputs: t.Sequence["TransactionOutput"]) -> int:
	input_size = 32 + 4 + 1 + 0 + 4
	base_size = 4
	base_size += len(crypto_utils.encode_varint(len(inputs)))
	base_size += len(inputs) * input_size
	base_size += len(crypto_utils.encode_varint(len(outputs)))
	base_size += sum(
		8
		+ len(crypto_utils.encode_varint(len(output.script_pubkey)))
		+ len(output.script_pubkey)
		for output in outputs
	)
	base_size += 4

	witness_size = 2
	if inputs:
		witness_size += len(inputs) * (1 + 1 + 64)
	weight = base_size * 4 + witness_size
	return (weight + 3) // 4


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
		if not isinstance(vout, int) or vout < 0:
			raise ValueError("vout must be a non-negative integer")
		if not isinstance(prevout_value_sats, int) or prevout_value_sats < 0:
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

	def serialize(self) -> bytes:
		script_sig = b""
		return (
			self._txid[::-1]
			+ crypto_utils.int_to_le_bytes(self._vout, 4)
			+ crypto_utils.encode_varint(len(script_sig))
			+ script_sig
			+ crypto_utils.int_to_le_bytes(self._sequence, 4)
		)


class TransactionOutput:
	"""Represents a Bitcoin transaction output."""

	def __init__(self, value_sats: int, script_pubkey: bytes) -> None:
		if not isinstance(value_sats, int) or value_sats < 0:
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

	def serialize(self) -> bytes:
		return (
			crypto_utils.int_to_le_bytes(self._value_sats, 8)
			+ crypto_utils.encode_varint(len(self._script_pubkey))
			+ self._script_pubkey
		)


class Transaction:
	"""Represents an immutable SegWit transaction."""

	def __init__(
		self,
		inputs: t.Iterable[TransactionInput],
		outputs: t.Iterable[TransactionOutput],
		fee_rate_sat_vbyte: int,
		change_address: address.TaprootAddress | None = None,
		version: int = 2,
		locktime: int = 0,
	) -> None:
		normalized_inputs = tuple(inputs) if inputs else tuple()
		if not normalized_inputs:
			raise ValueError("inputs are required")
		self._version = version
		self._locktime = locktime

		outputs_list = list(outputs)
		if not outputs_list:
			raise ValueError("outputs are required")
		if fee_rate_sat_vbyte <= 0:
			raise ValueError("fee_rate_sat_vbyte must be positive")

		fee_sats: int | None = None
		change_sats: int | None = None
		estimated_vbytes: int | None = None
		total_input_sats: int | None = None

		total_input_sats_calc = sum(
			inp.prevout_value_sats for inp in normalized_inputs
		)
		total_output_sats = sum(output.value_sats for output in outputs_list)
		estimated_vbytes_calc = _estimate_vbytes(normalized_inputs, outputs_list)
		fee_sats_calc = total_input_sats_calc - total_output_sats
		if fee_sats_calc < 0:
			raise ValueError("insufficient funds for outputs")

		fee_no_change = estimated_vbytes_calc * fee_rate_sat_vbyte
		change_no_change = total_input_sats_calc - total_output_sats - fee_no_change
		if change_no_change < 0:
			raise ValueError("insufficient funds for outputs and fee")

		dust_threshold_sats = 330

		if change_address is None:
			fee_sats = fee_no_change + change_no_change
			change_sats = 0
			estimated_vbytes = estimated_vbytes_calc
			total_input_sats = total_input_sats_calc
			outputs = outputs_list
		elif change_no_change < max(dust_threshold_sats, fee_no_change):
			fee_sats = fee_no_change + change_no_change
			change_sats = 0
			estimated_vbytes = estimated_vbytes_calc
			total_input_sats = total_input_sats_calc
			outputs = outputs_list
		else:
			outputs_with_change = [
				*outputs_list,
				TransactionOutput(
					value_sats=0,
					script_pubkey=_scriptpubkey_from_target(change_address),
				),
			]
			estimated_vbytes_change = _estimate_vbytes(
				normalized_inputs, outputs_with_change
			)
			fee_with_change = estimated_vbytes_change * fee_rate_sat_vbyte
			change_with_change = (
				total_input_sats_calc
				- total_output_sats
				- fee_with_change
			)
			if change_with_change < 0:
				raise ValueError("insufficient funds for change output and fee")

			if change_with_change < max(dust_threshold_sats, fee_with_change):
				fee_sats = fee_no_change + change_no_change
				change_sats = 0
				estimated_vbytes = estimated_vbytes_calc
				total_input_sats = total_input_sats_calc
				outputs = outputs_list
			else:
				outputs_with_change[-1] = TransactionOutput(
					value_sats=change_with_change,
					script_pubkey=_scriptpubkey_from_target(change_address),
				)
				fee_sats = fee_with_change
				change_sats = change_with_change
				estimated_vbytes = estimated_vbytes_change
				total_input_sats = total_input_sats_calc
				outputs = outputs_with_change

		self._inputs = normalized_inputs
		self._outputs = tuple(outputs) if outputs else tuple()
		self._fee_rate_sat_vbyte = fee_rate_sat_vbyte
		self._fee_sats = fee_sats
		self._change_sats = change_sats
		self._estimated_vbytes = estimated_vbytes
		self._total_input_sats = total_input_sats

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
	def locktime(self) -> int:
		return self._locktime

	@property
	def fee_rate_sat_vbyte(self) -> int | None:
		return self._fee_rate_sat_vbyte

	@property
	def fee_sats(self) -> int | None:
		return self._fee_sats

	@property
	def change_sats(self) -> int | None:
		return self._change_sats

	@property
	def estimated_vbytes(self) -> int | None:
		return self._estimated_vbytes

	@property
	def total_input_sats(self) -> int | None:
		return self._total_input_sats

	@property
	def is_signed(self) -> bool:
		return any(inp.has_witness for inp in self._inputs)

	def to_bytes(self, include_witness: bool = True) -> bytes:
		use_witness = include_witness and any(inp.has_witness for inp in self._inputs)
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
			for tx_input in self._inputs:
				witness = tx_input.witness
				result += crypto_utils.encode_varint(len(witness))
				for item in witness:
					result += crypto_utils.encode_varint(len(item)) + item
		result += crypto_utils.int_to_le_bytes(self._locktime, 4)
		return result

	def to_hex(self, include_witness: bool = True) -> str:
		return self.to_bytes(include_witness=include_witness).hex()

	def txid(self) -> bytes:
		return crypto_utils.double_sha256(self.to_bytes(include_witness=False))[::-1]

	def txid_hex(self) -> str:
		return self.txid().hex()


class TaprootSigner:
	"""Signing helpers for P2TR key-path spends."""

	@staticmethod
	def sighash(
		transaction: Transaction, input_index: int, hash_type: int = 0x00
	) -> bytes:
		if hash_type not in (0x00, 0x01):
			raise ValueError("hash_type must be 0x00 or 0x01")
		if input_index < 0 or input_index >= len(transaction.inputs):
			raise IndexError("input_index out of range")

		hash_prevouts = crypto_utils.sha256(
			b"".join(
				tx_input.txid[::-1]
				+ crypto_utils.int_to_le_bytes(tx_input.vout, 4)
				for tx_input in transaction.inputs
			)
		)
		hash_amounts = crypto_utils.sha256(
			b"".join(
				crypto_utils.int_to_le_bytes(tx_input.prevout_value_sats, 8)
				for tx_input in transaction.inputs
			)
		)
		hash_scriptpubkeys = crypto_utils.sha256(
			b"".join(
				crypto_utils.encode_varint(len(tx_input.prevout_script_pubkey))
				+ tx_input.prevout_script_pubkey
				for tx_input in transaction.inputs
			)
		)
		hash_sequences = crypto_utils.sha256(
			b"".join(
				crypto_utils.int_to_le_bytes(tx_input.sequence, 4)
				for tx_input in transaction.inputs
			)
		)
		hash_outputs = crypto_utils.sha256(
			b"".join(tx_output.serialize() for tx_output in transaction.outputs)
		)

		spend_type = 0x00
		sigmsg = (
			b"\x00"
			+ bytes([hash_type])
			+ crypto_utils.int_to_le_bytes(transaction.version, 4)
			+ crypto_utils.int_to_le_bytes(transaction.locktime, 4)
			+ hash_prevouts
			+ hash_amounts
			+ hash_scriptpubkeys
			+ hash_sequences
			+ hash_outputs
			+ bytes([spend_type])
			+ crypto_utils.int_to_le_bytes(input_index, 4)
		)
		return crypto_utils.tagged_hash("TapSighash", sigmsg)

	@staticmethod
	def sign_keypath(
		transaction: Transaction,
		input_index: int,
		priv_key: private_key.PrivateKey,
		merkle_root: bytes = b"",
		aux_rand: bytes | None = None,
		hash_type: int = 0x00,
	) -> Transaction:
		msg = TaprootSigner.sighash(
			transaction=transaction, input_index=input_index, hash_type=hash_type
		)
		signature = TaprootSigner._sign_schnorr(
			priv_key=priv_key, msg=msg, aux_rand=aux_rand, merkle_root=merkle_root
		)
		if input_index < 0 or input_index >= len(transaction.inputs):
			raise IndexError("input_index out of range")

		updated_inputs = list(transaction.inputs)
		updated_inputs[input_index] = updated_inputs[input_index].with_witness(
			[signature]
		)
		return Transaction(
			inputs=updated_inputs,
			outputs=transaction.outputs,
			version=transaction.version,
			locktime=transaction.locktime,
			fee_rate_sat_vbyte=transaction.fee_rate_sat_vbyte,
		)

	@staticmethod
	def _sign_schnorr(
		priv_key: private_key.PrivateKey,
		msg: bytes,
		aux_rand: bytes | None,
		merkle_root: bytes,
	) -> bytes:
		if len(msg) != 32:
			raise ValueError("msg must be 32 bytes")
		if aux_rand is None:
			aux_rand = secrets.token_bytes(32)
		if len(aux_rand) != 32:
			raise ValueError("aux_rand must be 32 bytes")
		if merkle_root not in (b"",) and len(merkle_root) != 32:
			raise ValueError("merkle_root must be empty or 32 bytes")

		d0 = priv_key.to_int
		pub_point = secp256k1_curve.G.multiply(d0)

		if pub_point.y % 2 != 0:
			d0 = secp256k1_curve.SECP256K1_ORDER - d0
			pub_point = secp256k1_curve.G.multiply(d0)

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
