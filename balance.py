import json
import urllib2

from cryptrtools import DOGEAddress, BTCAddress

def get_data(filename):
	f = open(filename)
	data_txt = f.read()

	data = json.loads(data_txt)
	return data

def addresses_total(addresses):
	total = 0
	for address in addresses:
		response = balance(address) # query web api
		print '{} has {} coins'.format(address.base58_address(), response)
		total += float(response)
	return total

def balance(address):
	request_url = address.request_url()
	url_f = urllib2.urlopen(request_url)
	response = url_f.read()
	return float(response)


print "Calculating metadata..."
doge_addresses = [DOGEAddress(str(doge['pk'])) for doge in get_data('dogeaddr.txt')]
print "Querying online API..."
total = addresses_total(doge_addresses)
print 'total:', total