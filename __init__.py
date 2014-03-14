from numutils import Address

class BTCAddress(Address):
	NETWORK_HEX = '00'

class LTCAddress(Address):
	NETWORK_HEX = '30'

class DOGEAddress(Address):
	NETWORK_HEX = '1e'

	def request_url(self):
		return 'https://dogechain.info/chain/CHAIN/q/addressbalance/{}'.format(self.base58_address())