import urllib
import base64
#import Template
import re

def URLEnc(msg):
	return urllib.quote_plus(msg)

def URLDec(msg):
	return urllib.unquote(msg)

def Base64Enc(msg):
	return base64.standard_b64encode(msg)

def Base64Dec(msg):
	return base64.standard_b64decode(msg)

def AsciiHexEnc(msg):
	return msg.encode('hex')

def AsciiHexDec(msg):
	return msg.decode('hex')

def BinEnc(msg):
	for ele in re.findall("[-+]?[.]?[\d]+(?:,\d\d\d)*[\.]?\d*(?:[eE][-+]?\d+)?", a):
		temp=bin(int(ele)).split('b')[1]
		print type(temp)
		a=a.replace(ele,temp )
		print a
	print a

a="My name is aastha56.5 \ p t . = ppp10"
#print HexEnc(a)
#print HexDec(HexEnc(a))
print bin(5).split('b')[1]
print re.findall(r'[0-9]',a)

print re.findall("[-+]?[.]?[\d]+(?:,\d\d\d)*[\.]?\d*(?:[eE][-+]?\d+)?", a)

for ele in re.findall("[-+]?[\d]+(?:,\d\d\d)*(?:[eE][-+]?\d+)?", a):
	temp=bin(int(ele)).split('b')[1]
	#print type(temp)
	print temp
	for i in a.find_all(ele):
		length= len(ele)
		if (not a[i-1].isdigit() and not a[i+len].isdigit()):
			a = a[:i+1] + temp + a[i+len:]
			print a
	print "bleh" 
print a
