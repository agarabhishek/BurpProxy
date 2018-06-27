from Crypto.Cipher import DES
import re
def DES_CBC_encrypt(key,iv,msg):
	cipherObj = DES.new(key, DES.MODE_CBC,iv)
	cipherText = cipherObj.encrypt(msg)
	return cipherText

def DES_CBC_decrypt(key,iv,msg):
	cipherObj = DES.new(key,DES.MODE_CBC,iv)
	plainText = cipherObj.decrypt(msg)
	#plainText = re.sub(r'[^\x20-\x7f]',r'',plainText)
	return plainText

key = "0123456789ABCDEF".decode('hex')
iv = "ABCDEF0123456789".decode('hex')
msg = "5FC1F3BC168F9F47CC9D4CA548010B5F".decode('hex')

msg2 = "aastha"

print DES_CBC_encrypt(key,iv,msg2)
print DES_CBC_decrypt(key,iv,msg)

