from ecdsa import SigningKey, VerifyingKey, SECP256k1

def sha256(hex_str):
	# input: hex. output: hex
	import hashlib
	ascii_str = hex_str.decode('hex')
	return hashlib.sha256(ascii_str).hexdigest()

def clean_hex_str(hex_str):
	# input: hex. output: hex
	if hex_str[-1] == 'L':
		hex_str = hex_str[:-1]

	if hex_str[0:2] == '0x':
		hex_str = hex_str[2:]

	return hex_str

def checksum(hex_str):
	# input: hex. output: hex
	return sha256(sha256(hex_str))

def ripemd160(hex_str):
	# input: hex. output: hex
	import hashlib
	hash_function = hashlib.new('ripemd160')
	hash_function.update(hex_str.decode('hex'))
	return hash_function.hexdigest()

def hex_to_ascii(hex_str):
	ascii_string = ''
	x=0
	y=2
	l = len(hex_str)
	while y <= l:
		ascii_string += chr(int(hex_str[x:y], 16))
		x += 2
		y += 2
	return ascii_string

def hex_to_num(hex):
	return int(clean_hex_str(hex), 16)

def get_private_network_key(public):
	# input hex, output hex
	num = ((hex_to_num(public) + 128) & 255)
	return num_to_hex(num)

def num_to_hex(num):
	h = hex(num)[2:]
	return clean_hex_str(h)

class Base58(object):
	alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
	base_count = len(alphabet)

	@classmethod
	def encode(cls, hex_str):
		#input: hex, output: b58string
		num = long(hex_str, 16)
		encode = ''
		
		if (num < 0):
			return ''
		
		while (num >= cls.base_count):    
			mod = num % cls.base_count
			encode = cls.alphabet[mod] + encode
			num = num // cls.base_count
	 
		if (num):
			encode = cls.alphabet[num] + encode

		for i in range(0, len(hex_str), 2):
			if hex_str[i:i+2] == '00':
				encode = cls.alphabet[0] + encode
			else:
				break
	 
		return encode

	@classmethod
	def decode(cls, s):
		#input: b58string, output: hex
		""" Decodes the base58-encoded string s into an integer """
		decoded = 0
		multi = 1
		s = s[::-1]
		for char in s:
			decoded += multi * cls.alphabet.index(char)
			multi = multi * cls.base_count
			
		return num_to_hex(decoded)

def Base58checkFactory(version):
	class Inner(Base58):
		@classmethod
		def encode(cls, hex_str, enc_type=None):
			if enc_type == 'private': #20 bytes:
				v = get_private_network_key(version)
			else:
				v = version
			#input: hex, output: base58
			hex_str = v + hex_str
			return super(Inner, cls).encode( hex_str + checksum(hex_str)[:8] )

		@classmethod
		def decode(cls, b58_str):
			decoded = super(Inner, cls).decode( b58_str )[2:-8]
			return decoded

	return Inner

class DesKeyMixin(object):
	curve = SECP256k1

	def __init__(self, composing_key):
		self.composing_key = composing_key

	def to_hex(self):
		return self.composing_key.to_string().encode('hex')

	def to_string(self):
		return self.composing_key.to_string()

	@classmethod
	def from_hex(cls, hex_str):
		hex_str = clean_hex_str(hex_str)
		ascii_str = hex_to_ascii(hex_str)
		return cls(cls.Key.from_string(ascii_str, curve=cls.curve))

class PrivateKey(DesKeyMixin):
	Key = SigningKey

	def __init__(self, composing_key=None):
		if composing_key is None:
			composing_key = self.Key.generate(curve=self.curve)
		super(PrivateKey, self).__init__(composing_key)

	def get_public_key(self):
		return PublicKey(self.composing_key.get_verifying_key())

class PublicKey(DesKeyMixin):
	Key = VerifyingKey

	def to_hex(self):
		return '04'+super(PublicKey, self).to_hex()

	@classmethod
	def from_hex(cls, hex_str):
		return super(PublicKey, cls).from_hex(hex_str)

class Address(object):
	PREFIX = ''

	def __init__(self, private=None):
		self.Base58check = Base58checkFactory(self.NETWORK_HEX)
		if private is None:
			private = PrivateKey()
		elif type(private) is str:
			# verify that it's hex
			try:
				private = PrivateKey.from_hex(private)
			except ValueError:
				#it's not hex. assume it's a base58check private key
				private = PrivateKey.from_hex(self.Base58check.decode(private))
		self.private = private
		self.public = private.get_public_key()
		self.h160 = None
		self.base58 = None

	def hash160_address(self):
		if self.h160 is None:
			self.h160 = ripemd160(sha256(self.public.to_hex()))
		return self.h160

	def base58_address(self):
		if self.base58 is None:
			self.base58 = self.Base58check.encode(self.hash160_address()) # not private!
		return self.base58

	def wallet_import_format(self):
		return self.Base58check.encode(self.private.to_hex(), enc_type='private')