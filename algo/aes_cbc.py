from Crypto.Cipher import AES
import base64
import re
from Padding import appendPadding,removePadding

# MODES ={
# (0,'Bit')     : 'BitPadding: Pad with 0x80 (10000000) followed by zero (null) bytes. Described in ANSI X.923 and ISO/IEC 9797-1',
# (1,'CMS')     : 'Also called PKCS#5/PKCS#7. Pad with bytes all of the same value as the number of padding bytes. Default mode used in Cryptographic Message Syntax (CMS as defined in RFC 5652, PKCS#5, PKCS#7 and RFC 1423 PEM)',
# (2,'ZeroLen') : 'Also called ANSI X.923. Pad with zeroes except make the last byte equal to the number (length) of padding bytes',
# (3,'Null')    : 'Also called Zero Padding.Pad with null bytes. Only for encrypting of text data.',
# (4,'ISO')   : 'Known as ISO/IEC 7816-4. Pad with 80 (Hexadecimal) followed by 00.Identical to the bit padding scheme.',
# (5,'Random')  : 'Also called -ISO 10126. Pad with random bytes + last byte equal to the number of padding bytes'         
#        }

def aes_cbc_dec(key,cph_txt,iv,mode):

	# Decryption
	decryption_suite = AES.new(key, AES.MODE_CBC, iv)
	plain_txt_orig = decryption_suite.decrypt(cph_txt)
	plain_txt2=removePadding(plain_txt_orig, blocksize=16, mode=mode)
	return plain_txt2

def aes_cbc_enc(key,plain_txt,iv,mode):

	#Encryption
	encryption_suite = AES.new(key,AES.MODE_CBC,iv)
	plain_txt_pad=[]
	plain_txt_pad=appendPadding(plain_txt, blocksize=16, mode=mode)
	cph_txt=encryption_suite.encrypt(plain_txt_pad)
	return cph_txt
