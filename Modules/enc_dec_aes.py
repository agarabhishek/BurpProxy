from Crypto.Cipher import AES
from Padding import appendPadding,removePadding


blocksize=16  #Blocksize is 16,24 or 32 bytes in AES
#Key size is always 8 bytes(Blocksize).
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
