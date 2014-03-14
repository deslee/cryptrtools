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
			('address', lambda addr: addr.base58_address()),
			('public_key', lambda addr: addr.public.to_hex()),
			('public_hash160', lambda addr: addr.hash160_address()),
		]

		def test(self, name, addr_class):
			address = addr_class(self.private_key)
			for attr, addr_exp in self.map_attr_addr:
				eval_data = getattr(self,attr)
				eval_addr = addr_exp(address)
				result ="{}:{} '{}'=='{}'\n\t{}".format(name,attr,eval_data, eval_addr, eval_data == eval_addr)
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

	testing_doge = [
		TestingAddress(
			'569c50e4fbc104546f916f012b056b2bdd74c749d91b023a5277efe00e7a77ba',
			'6JnmE3H1pb6qPgJC84SwwABffqiQ8XNFHT9hupwripGDcEHWFk7',
			'DDDQqMUtvjrUnoZY4PSw9MMGnYpGcv3z4n',
			'0490416fc991c68f21847dc0719e4b5720308793650863ba4698dd3c566cf92bc0e82deb31800764f6c1a7792325d783ba8bfa19563d00852c55c1d71b4a9eea80',
			'5891f11a2b4be1e4949f66b3ff7903774f15554b',
		),
		TestingAddress(
			'583a1e5cb2d719fb5bd694ac1ec5acec056b528c3da0a7ae220ad36160d7052c',
			'6JoUWp79YqMhA6oJCjy2MW8uJyN3Biqkwye5Crv8p8neAKcgxi4',
			'D8kvigxXXoe8yQjxgs6sHmXEMNWVaoSSqu',
			'04d3d6d1b460e9fe7a9a1161db76f913dcdd2b860421b895d4c4b5e61dcf3c2ab4911de8d34b9da6815b2579a35f9fa4612aab61030ea9802518f497de6542e8e4',
			'27af278f19f84cbf17e4b8499f643e538edcb099',
		),
		TestingAddress(
			'53255d24be82fde89e9e6f981b78431f33103bedd75156f2f2b115c0f871cc66',
			'6JmEj3FFjZ3UeEm8KDDKRkvrapVHffvEbmRmNFFvG8tfQjKJH6R',
			'DFyDfKUzKUjBCMTmYYxPjVy5znqwTPTjX6',
			'04869df8876919d2d6155c956285ce854d441501a2f1f81259ec6384f1f841dd0595582dfe9c3c8a8dd95ed4a28c2bdc2dcb932361e5cfc20563ecceb33501c106',
			'76cb2b3f4c00c05f67599d2ae70402537dfb1e69',
		),
		TestingAddress(
			'a1d813fdf23c9841c8e057d2f06aef225f31616b593b9f4693ca3094d91fe0a3',
			'6KMtxosvEF5keHfVjbhCZ9EM5HxU43LvUduTf88pJwVdYMtvsBX',
			'DNdYC49QDU6a9CXYTQQb8SjSuLSoUbHboc',
			'0453d129e5840f62e3587a2d3318294c52c8067722e0bef03bfbfdebc264825a9eec9db77b1ec84722ecfb1825c80b36cbe68cc94aef85b80a62ab08024d011691',
			'bfdb32bc56be8890118518854119e6a352f4aa73',
		),
	]

	testing_ltc = [
		TestingAddress(
			'3bd8a0d6ae2b479cf90d520b2874b03492a44abc810d1c3efbfaab806c375eda',
			'6uaNjtQ35n8NLwetL2gQL8Di8DQDA3pT6E9xwVQUX6WmjLxZch8',
			'LQGCmZSKE4FRVjKVdotCAYQ9D68oJeEop8',
			'0405b242da1bbb4fbaeed794a9f384cea9c48d4f8d48ded89e91f8310360fef8a34e17f08f6601289d8a0bc479338f2ed7792dc6a76a8e1588f8e1deb6c233d7db',
			'374591e03c8c53cc633cb432bbc66296367b2bcb',
		),
		TestingAddress(
			'c42ccb59d9561b70522188e43a96797b3729cb78d92ca002a1bd32457648bea7',
			'6vcR5MC7nMytqWnUV5yo47eYwBrzFHy1CHfGmsaf87a6JJDYBF5',
			'LTVit1gNAY2gV3J6xCdLJp35qLsk6Wua5j',
			'0438057457126c1bf4b9935d49164ecd24c496f24382f370f7b743792f25d2dd286015cd176bf488432bdc6824bae0f664f423eea4b64171d7dc4f588e345f98e2',
			'5abc7d8379ef198a5df47d52a8c625111cb91ab1',
		),
		TestingAddress(
			'67350602ec9f935295601c6c50a9d7e8141849cc3b0e080943099f0d7e979e8e',
			'6uuULUwC8vmcxmF6gkGQQeqD9VmS3DKpUseyStah4cD1Pxd8ore',
			'LXq96Ph5Tirp4zuhH1ovfzEptn7f3nvwp4',
			'042ee36474384dc9afd5d3eba8b485cb40bc35b7e46d819552482c53d5e950f6e0ab40e5dc8f9442883d626d510a5fe74cfd7336adf590618aa6ea48ecc2bfd672',
			'8a491beb3ffbde4f95d62580a15dcbc9f0174ef5',
		),
	]

	for address in testing_btc:
		address.test('btc', BTCAddress)
		raw_input("press enter to continue...")

	for address in testing_doge:
		address.test('doge', DOGEAddress)
		raw_input("press enter to continue...")

	for address in testing_ltc:
		address.test('ltc', LTCAddress)
		raw_input("press enter to continue...")

	print('end')