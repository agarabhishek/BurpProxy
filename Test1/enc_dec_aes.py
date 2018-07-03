from Crypto.Cipher import AES
from Padding import appendPadding,removePadding
import base64
import json

blocksize=16  #Key is 16,24 or 32 bytes in AES
#Blocksize is always 16 bytes.
#IV is usually Blocksize long. Except for OpenPGP Mode.
#segment_size is used only in CFB Mode. It must be a multiple of 8. If 0 or not specified, it will be assumed to be 8.

# 3 AES Modes -CBC,EBC and CFB are handled.
# All padding modes are handled. The list is given below.

# MODES ={
# (0,'Bit')     : 'BitPadding: Pad with 0x80 (10000000) followed by zero (null) bytes. Described in ANSI X.923 and ISO/IEC 9797-1',
# (1,'CMS')     : 'Also called PKCS#5/PKCS#7. Pad with bytes all of the same value as the number of padding bytes. Default mode used in Cryptographic Message Syntax (CMS as defined in RFC 5652, PKCS#5, PKCS#7 and RFC 1423 PEM)',
# (2,'ZeroLen') : 'Also called ANSI X.923. Pad with zeroes except make the last byte equal to the number (length) of padding bytes',
# (3,'Null')    : 'Also called Zero Padding.Pad with null bytes. Only for encrypting of text data.',
# (4,'ISO')   : 'Known as ISO/IEC 7816-4. Pad with 80 (Hexadecimal) followed by 00.Identical to the bit padding scheme.',
# (5,'Random')  : 'Also called -ISO 10126. Pad with random bytes + last byte equal to the number of padding bytes'         
# }


def aes_ecb_enc(key,plain_txt,mode):

	#Encryption of AES-EBC
	global blocksize
	encryption_suite=AES.new(key,AES.MODE_EBC)
	plain_txt_pad=appendPadding(plain_txt,blocksize=blocksize,mode=mode)
	cph_txt=encryption_suite.encrypt(plain_txt_pad)
	return cph_txt

def aes_ecb_dec(key,cph_txt,mode):

	#Decryption of AES-EBC
	global blocksize
	decryption_suite=AES.new(key,AES.MODE_EBC)
	plain_txt_orig=decryption_suite.decrypt(cph_txt)
	plain_txt=removePadding(plain_txt_orig,blocksize=blocksize,mode=mode)
	return plain_txt




def aes_cbc_enc(key,plain_txt,iv,mode):

	#Encryption of AES-CBC
	global blocksize
	encryption_suite = AES.new(key,AES.MODE_CBC,iv)
	plain_txt_pad=appendPadding(plain_txt, blocksize=blocksize, mode=mode)
	cph_txt=encryption_suite.encrypt(plain_txt_pad)
	return cph_txt

def aes_cbc_dec(key,cph_txt,iv,mode):

	# Decryption of AES-CBC
	global blocksize
	decryption_suite = AES.new(key, AES.MODE_CBC, iv)
	plain_txt_orig = decryption_suite.decrypt(cph_txt)
	plain_txt=removePadding(plain_txt_orig, blocksize=blocksize, mode=mode)
	return plain_txt




def aes_cfb_enc(key,plain_txt,iv,mode,segment_size):

	#Encryption for AES-CFB
	global blocksize
	encryption_suite=AES.new(key,AES.MODE_CFB,iv,segment_size=segment_size)
	plain_txt_pad=appendPadding(plain_txt,blocksize=blocksize,mode=mode)
	cph_txt=encryption_suite.encrypt(plain_txt_pad)
	return cph_txt


def aes_cfb_dec(key,cph_txt,iv,mode,segment_size):

	#Decryption for AES-CFB
	global blocksize
	decryption_suite=AES.new(key,AES.MODE_CFB,iv,segment_size=segment_size)
	plain_txt_orig=decryption_suite.decrypt(cph_txt)
	plain_txt=removePadding(plain_txt_orig,blocksize=blocksize,mode=mode)
	return plain_txt



# There are 4 other modes. Have similar structure. Number of arguments may differ depending upon the mode.
# Resource- https://www.dlitz.net/software/pycrypto/api/2.6/ 
d="d2WSgZvHd6Vabjs/oTl5DPG7ILrhEuvgF36FTcsJKLSJ8WOSyAH4E7NHcamdUFO5gyg8zTriG1uXp13fP6XOhPl+hKFcRbuakhqwdKUhsNrGQFN+3Z+ryiuyzxpdggJQKUf39m3w4if/jEZ8p1RpjyKBCQ9RZoP+41ai5G6d1B94yXBnO3OwIXKLCzrLKd7U4LGmNLu5fTvtFcvLJEUjRLFR90XWWjotHF25VWqLjTOAyk30cwkD6wTHqLpB3oBK9fYVV3NVhrBXHbZcTLmcdz0eE1haTxtuClp40y8WvX3UKu+FVi2XAI07LlESXo7OGnt7IHwdomGJDWY+1gUVg0FDhVEsaF7w23rTBliKf0DWeeEpUrsqT7/tzRZPGt5uHoliONqHdeN8OVRA/VAMOzMk63R4nNHP7BDk+Yt7AAEx6KNbB5ucgqVyTSnygVrPpIcbxWVzlY0WnRxHgbp4pUyJWwnTqmSGQeTTQxyRjsvgMzTQnbFfGOCArkU2x/xTogixVef1ir16jAYHQJuQunV5yQpBeDd4cuiHIU9TnxUArqaFrQHk4KW8LzwCQnzs3U09LgOjiO4hs9RG9xz/4ZgCrpBeo3oKIdRzZIveigviyzMM1vaVIFNRjIW5wgnLuxSJ99a7X/I4DbSfdXyMITYR3CVByFemoI3NzYBYg1m7rdAE22k4AqewCmcTj3kWGGI1ti4BrhLfApKgk3OWpJHHx59nMHGYRV7N5bR8qOA+tJekL0byPS7wPhYVViUw"
e=base64.b64decode(d)
print(aes_cbc_dec("441538f57b510c0512f594c213cc523c",e[16:],e[0:16],"CMS"))
print base64.b64encode(e[:16])+aes_cbc_dec("441538f57b510c0512f594c213cc523c",e[16:],e[0:16],"CMS")
# decrpt =aes_cbc_dec("441538f57b510c0512f594c213cc523c",e[16:],e[0:16],"CMS")
# json_obj = json.loads(decrpt)
# for ele in json_obj.keys():
# 	print "Encrypt " + ele + "(Y/N)"
#         choice =raw_input()
#         if (choice=='Y' or choice=='y'):
#         	json_obj[ele] = raw_input()
# print json_obj
# json_str= json.dumps(json_obj,indent=2)
# print json_str
# encrpt= aes_cbc_enc("441538f57b510c0512f594c213cc523c",json_str,e[0:16],"CMS")
# print base64.b64encode(e[:16]+encrpt)
