class DesAddress(object):
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
