from ecdsa import SigningKey, VerifyingKey, SECP256k1
import struct

class Base58(object):
	alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

class Binary(object):
	def __init__(self, _bytes):
		self.bytes = _bytes

	@classmethod
	def from_integer(cls, integer):
		array = bytearray()
		while integer > 0:
			b = struct.pack('B', integer & 0xff)
			array.insert(0,b[0])
			integer = integer >> 8
		return Binary(array)

	@classmethod
	def from_hexidecimal(cls, hexidecimal):
		if type(hexidecimal) is int:
			return Binary.from_integer(hexidecimal)
		elif type(hexidecimal) is str:
			return Binary(bytes.from_hexidecimal(hexidecimal))

	@classmethod
	def from_base58(cls, s):
		alphabet = Base58.alphabet

		decoded = 0
		multi = 1
		s = s[::-1]
		for char in s:
			decoded += multi * alphabet.index(char)
			multi = multi * len(alphabet)

		return Binary(decoded)

	def __str__(self):
		return str(self.bytes)

b = Binary.from_integer('0200')
print(str(b))