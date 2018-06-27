from Crypto.Cipher import DES
from Padding import appendPadding,removePadding

blocksize=8  #Blocksize is 8 bytes in DES
#Key size is always 8 bytes(Blocksize).
#IV is usually Blocksize long. Except for OpenPGP Mode.
#segment_size is used only in CFB Mode. It must be a multiple of 8. If 0 or not specified, it will be assumed to be 8.

# 3 DES Modes -CBC,EBC and CFB are handled.
# All padding modes are handled. The list is given below.

# MODES ={
# (0,'Bit')     : 'BitPadding: Pad with 0x80 (10000000) followed by zero (null) bytes. DEScribed in ANSI X.923 and ISO/IEC 9797-1',
# (1,'CMS')     : 'Also called PKCS#5/PKCS#7. Pad with bytes all of the same value as the number of padding bytes. Default mode used in Cryptographic Message Syntax (CMS as defined in RFC 5652, PKCS#5, PKCS#7 and RFC 1423 PEM)',
# (2,'ZeroLen') : 'Also called ANSI X.923. Pad with zeroes except make the last byte equal to the number (length) of padding bytes',
# (3,'Null')    : 'Also called Zero Padding.Pad with null bytes. Only for encrypting of text data.',
# (4,'ISO')   : 'Known as ISO/IEC 7816-4. Pad with 80 (Hexadecimal) followed by 00.Identical to the bit padding scheme.',
# (5,'Random')  : 'Also called -ISO 10126. Pad with random bytes + last byte equal to the number of padding bytes'         
# }


def des_ecb_enc(key,plain_txt,mode):

	#Encryption for des-ECB
	global blocksize
	encryption_suite=DES.new(key,DES.MODE_ECB)
	plain_txt_pad=appendPadding(plain_txt,blocksize=blocksize,mode=mode)
	cph_txt=encryption_suite.encrypt(plain_txt_pad)
	return cph_txt

def des_ecb_dec(key,cph_txt,mode):

	#Decryption for des-ECB
	global blocksize
	decryption_suite=DES.new(key,DES.MODE_ECB)
	plain_txt_orig=decryption_suite.decrypt(cph_txt)
	plain_txt=removePadding(plain_txt_orig,blocksize=blocksize,mode=mode)
	return plain_txt



def des_cbc_enc(key,plain_txt,iv,mode):

	#Encryption for des-CBC
	global blocksize
	encryption_suite=DES.new(key,DES.MODE_CBC,iv)
	plain_txt_pad=appendPadding(plain_txt,blocksize=blocksize,mode=mode)
	cph_txt=encryption_suite.encrypt(plain_txt_pad)
	return cph_txt

def des_cbc_dec(key,cph_txt,iv,mode):

	#Decryption for des-CBC
	global blocksize
	decryption_suite=DES.new(key,DES.MODE_CBC,iv)
	plain_txt_orig=decryption_suite.decrypt(cph_txt)
	plain_txt=removePadding(plain_txt_orig,blocksize=blocksize,mode=mode)
	return plain_txt




def des_cfb_enc(key,plain_txt,iv,mode,segment_size):

	#Encryption for des-CFB
	global blocksize
	encryption_suite=DES.new(key,DES.MODE_CFB,iv,segment_size=segment_size)
	plain_txt_pad=appendPadding(plain_txt,blocksize=blocksize,mode=mode)
	cph_txt=encryption_suite.encrypt(plain_txt_pad)
	return cph_txt

def des_cfb_dec(key,cph_txt,iv,mode,segment_size):

	#Decryption for des-CFB
	global blocksize
	decryption_suite=DES.new(key,DES.MODE_CFB,iv,segment_size=segment_size)
	plain_txt_orig=decryption_suite.decrypt(cph_txt)
	plain_txt=removePadding(plain_txt_orig,blocksize=blocksize,mode=mode)
	return plain_txt



# There are 4 other modes. Have similar structure. Number of arguments may differ depending upon the mode.
# Resource- https://www.dlitz.net/software/pycrypto/api/2.6/ 