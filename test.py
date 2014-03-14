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

def num_to_hex(num):
	h = hex(num)[2:]
	return clean_hex_str(h)

class Base58(object):
	alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
	base_count = len(alphabet)

	@classmethod
	def encode(cls, hex_str):
		#input: hex, output: b58
		num = long(hex_str, 16)
		""" Returns num in a base58-encoded string """
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
		#input: b58, output: hex
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
		def encode(cls, hex_str, type):
			#input: hex, output: base58
			v = version[type]
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

	def hash160(self):
		if self.h160 is None:
			self.h160 = ripemd160(sha256(self.public.to_hex()))
		return self.h160

	def to_base58check(self):
		if self.base58 is None:
			self.base58 = self.Base58check.encode(self.hash160(), 0)
		return self.base58

	def wallet_import_format(self):
		return self.Base58check.encode(self.private.to_hex(), 1)

class BTCAddress(Address):
	NETWORK_HEX = ['00', '80']

class LTCAddress(Address):
	NETWORK_HEX = ['30']

class DOGEAddress(Address):
	NETWORK_HEX = ['1E']

if __name__ == '__main__':
	class TestingAddress(object):
		def __init__(self, secret, private_key, address, public_key, public_hash160):
			self.secret = secret
			self.private_key = private_key
			self.address = address
			self.public_key = public_key
			self.public_hash160 = public_hash160

		map_attr_addr = [
			('secret', lambda addr: addr.private.to_hex()),
			('private_key', lambda addr: addr.wallet_import_format()),
			('address', lambda addr: addr.to_base58check()),
			('public_key', lambda addr: addr.public.to_hex()),
			('public_hash160', lambda addr: addr.hash160()),
		]

		def test_btc(self):
			address = BTCAddress(self.secret)
			for attr, addr_exp in self.map_attr_addr:
				eval_data = getattr(self,attr)
				eval_addr = addr_exp(address)
				result ="{}:'{}'=='{}'\n\t{}".format(attr,eval_data, eval_addr, eval_data == eval_addr)
				print(result)

	testing_btc = [
		TestingAddress(
			'ab99bbf221442fab9f752ffe888e04ef71c91c85cff986885930779e121b9edd',
			'5K7rtNivvMssDxikLBJMNDvzsBWWj4Z9D4HbUntDowW4iVaQ3Pc',
			'1HyNdxtapMbp2JakTCpBwZ9qoeEc8f95Vd',
			'04a6fb2633861f4333ebed65a657583d9fa25d32335033c57b659b5454fd1282393a942a2983e3b1142915a253e49b6bbd5eed89129d61a0a6f6ebe30daa3412bb',
			'ba2b5e49b3c9aaa89f8ddce2ce66799582412fe1',
		),
		TestingAddress(
			'95f68f23c5585c0ee06b1f01f3a6ea59e8eded780303feafa3d591130125c2b0',
			'5JxLBsHn2avAy8RB2pEnFfbfy2Xms1su66BC12LSE5oqqUjjfz6',
			'1ExedysajGhfC19qTW5KzHGXnTLmjYZ135',
			'04b28bbd839e28868e069782a05d95410ae2e442da68031edf5934d854eebfe285690ec817bea92826e551fd1b2254bf539d75bf892b52534046c9e2a4306e1711',
			'991fee6e479db3d73e3efe396a139c1c6739c623',
		),
		TestingAddress(
			'bf510f18d74099bbd65f1ebe1640796aedec051e2c04e8c3140fc3099ccff992',
			'5KGYWRtyWPunhdUJQdYaLF7Mdio5Vax82FFAbSeXamLqtqdMqMR',
			'1ABFP88HeaVgzDHHqgfTNSG4sKJwZ3WWjD',
			'0428e89bcf2ab99d4c9db82432bf10f621394b43cce1986b3a6a77564be00adeab574ea38a2f7b37f7eacc2f139ee3568600d03d8fe7ad3c73776a40aeacdff995',
			'64a94bf3797778e2b6a7269aeb202e53b324f115',
		),
		TestingAddress(
			'4a744dd45d2677255cf78351b52dc12d8f2748c06296a1a8d966d7fc97ea646e',
			'5JP5R92aBSSw7Bo2G59xkdywd8ZqCtz7iRz42VSTNeVQXa1iECr',
			'1521oYVf1YoBEUoxwkMX3M8VAcHyuwesGc',
			'04133338f4f902e967a5788f38e25772f2393f446f4bda44ee42f535b617cdb4631258b67546155cb69f52ed4346a1756209cfa0b1bf0756910870622a7e3510fb',
			'2c1196c62c846acef82b5206fd6a268c168547df',
		),
	]

	for address in testing_btc:
		address.test_btc()
		raw_input("press enter to continue...")

	print('end')