from ecdsa import SigningKey, VerifyingKey, SECP256k1

def sha256(hex_str):
	# input: hex. output: hex
	import hashlib
	ascii_str = hex_str.decode('hex')
	return hashlib.sha256(ascii_str).hexdigest()

def clean_hex_str(hex_str):
	if hex_str[-1] == 'L':
		hex_str = hex_str[:-1]

	if hex_str[0:2] == '0x':
		hex_str = hex_str[2:]

	return hex_str

def checksum(hex_str):
	return sha256(sha256(hex_str))

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
    def encode(cls, hex):
    	#input: hex, output: b58

    	num = int(hex, 16)
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

class Base58check(Base58):
	@classmethod
	def encode(cls, hex):
		#input: hex, output: base58
		return super(Base58check, cls).encode( hex + checksum(hex)[:8] )

	@classmethod
	def decode(cls, b58_str):
		#input: base58, output: hex
		return super(Base58check, cls).decode( b58_str )[:-8]

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
	HASH_TYPE = 'ripemd160'

	def __init__(self, private=None):
		if private is None:
			private = PrivateKey()
		elif type(private) is str:
			# verify that it's hex
			try:
				private = PrivateKey.from_hex(private)
			except ValueError:
				#it's not hex. assume it's a base58check private key
				print(Base58check.decode(private))
				private = PrivateKey.from_hex(Base58check.decode(private))
		self.private = private
		self.public = private.get_public_key()
		self.h160 = None
		self.base58 = None

	def hash160(self):
		if self.h160 is None:
			import hashlib
			sha = sha256(self.public.to_hex())
			hash_function = hashlib.new(self.HASH_TYPE)
			hash_function.update(sha.decode('hex'))
			self.h160 = '{}{}'.format(self.NETWORK_HEX, hash_function.hexdigest())
		return self.h160

	def to_base58check(self):
		if self.base58 is None:
			self.base58 = Base58check.encode(self.h160)
		return self.PREFIX + self.base58

class BTCAddress(Address):
	NETWORK_HEX = '00'
	PREFIX = '1'

class LTCAddress(Address):
	NETWORK_HEX = '30'

class DOGEAddress(Address):
	NETWORK_HEX = '1E'

if __name__ == '__main__':
	# taken from bitcoin wiki
	pk = '18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725'
	print 'private key:', pk
	addr = BTCAddress(pk)
	print 'ripemd', addr.hash160()
	print 'base58 address:', addr.to_base58check()