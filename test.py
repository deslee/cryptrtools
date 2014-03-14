from ecdsa import SigningKey, VerifyingKey, SECP256k1

def sha256(cls, hex):
	import hashlib
	ascii_str = hex.decode('hex')
	return hashlib.sha256(ascii_str).hexdigest()

class Base58(object):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    base_count = len(alphabet)

    @classmethod
    def encode(cls, num):
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
        """ Decodes the base58-encoded string s into an integer """
        decoded = 0
        multi = 1
        s = s[::-1]
        for char in s:
            decoded += multi * cls.alphabet.index(char)
            multi = multi * cls.base_count
            
        return decoded

class Base58Check(Base58):
	# in: int, out: b58chk
	def encode(cls, num):
		result = super(Base58Check, cls).encode(num)
		chksum = sha256(sha256(num).digest()).digest()

class DesKeyMixin(object):
	curve = SECP256k1

	@staticmethod
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

	def __init__(self, composing_key):
		self.composing_key = composing_key

	def to_hex(self):
		return self.composing_key.to_string().encode('hex')

	def to_string(self):
		return self.composing_key.to_string()

	@classmethod
	def from_hex(cls, hex_str):
		if hex_str[0:2] == '0x':
			hex_str = hex_str[2:]
		ascii_str = cls.hex_to_ascii(hex_str)
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
		return super(PublicKey, cls).from_hex(hex_str[2:-1])

class Address(object):
	PREFIX = ''
	RIPE_HASH = 'ripemd160'

	def __init__(self, private=None):
		if private is None:
			private = PrivateKey()
		elif type(private) is str:
			# verify that it's hex
			try:
				int(private, 16)
			except ValueError:
				# then it's probably base58check
				private = hex(Base58.decode(private))
				pass
			print private
			private = PrivateKey.from_hex(private)
		self.private = private
		self.public = private.get_public_key()
		self.ripe = None
		self.cksum = None
		self.base58 = None


	def ripen(self):
		if self.ripe is None:
			import hashlib
			sha256 = sha256(self.public.to_hex())
			ripe = hashlib.new(self.RIPE_HASH)
			ripe.update(sha256.decode('hex'))
			self.ripe = '{}{}'.format(self.NETWORK_HEX, ripe.hexdigest())
		return self.ripe	

	def checksum(self):
		if self.cksum is None:
			ripe = self.ripen()
			sha256 = sha256(ripe)
			self.cksum = sha256(sha256)[0:8]
		return self.cksum 

	def to_hex(self):
		return self.ripen() + self.checksum()

	def to_int(self):
		return int(self.to_hex(), 16)

	def to_base58(self):
		if self.base58 is None:
			self.base58 = Base58.encode(self.to_int())
		return self.PREFIX + self.base58

class BTCAddress(Address):
	NETWORK_HEX = '00'
	PREFIX = '1'

class LTCAddress(Address):
	NETWORK_HEX = '30'

class DOGEAddress(Address):
	NETWORK_HEX = '1E'

if __name__ == '__main__':
	s = None
	print 'private key:', s
	addr = DOGEAddress(s)
	print 'base58 address:', addr.to_base58()