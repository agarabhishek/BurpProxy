#Encoder Decoder for Base64, ASCIIHex, Hex, Octal, Binary, URL
import urllib
import base64
import re

#Function to URL Encode. Uses urllib library's quote_plus() function. 
def URLEnc(msg):
	return urllib.quote_plus(msg)

#Function to URL Deocde. Uses urllib library's unquote() function.
def URLDec(msg):
	return urllib.unquote(msg)

#Function to Base64 Encode. Converts to standard base 64 characters.
def Base64Enc(msg):
	return base64.b64encode(msg)

#Function to Base64 Decode. Converts from standard base 64 characters to ASCII.
def Base64Dec(msg):
	return base64.b64decode(msg)

#Function to ASCII Hex Encode. Entire message(characters+digits) are encoded to hex.
def AsciiHexEnc(msg):
	return msg.encode('hex')

#Function to ASCII Hex Decode. Hex encoded message is converted to ASCII.
def AsciiHexDec(msg):
	return msg.decode('hex')

#Function to Binary Encode. Only digits present in the message are converted to Binary.
def BinEnc(a):
	for ele in re.findall("[\d]+(?:,\d\d\d)*?", a):
		temp=bin(int(ele)).split('b')[1]
		for i in re.finditer(ele,a):
			length= len(ele) 
			if (i.start()==0 and i.end()==len(a)):
				a=temp
			elif (i.start()==0 and not a[i.end()].isdigit()):
				a= temp + a[i.end():]
			elif (i.end()==len(a) and not a[i.start()-1].isdigit()):
				a = a[:i.start()] + temp 
			elif (not a[i.start()-1].isdigit() and not a[i.end()].isdigit()):
				a = a[:i.start()] + temp + a[i.end():]
	return a

#Function to Binary Encode. Only digits present in the message are converted to Binary.
def BinDec(a):
	for ele in re.findall("[\d]+(?:,\d\d\d)*?", a):
		temp=str(int(ele,2))
		counter=0
		#print temp
		for i in re.finditer(ele,a):
			length= len(ele)
			#print i.start()
			#print i.end()
			if (i.start()>=counter):
				if (i.start()==0 and i.end()==len(a)):
					a=temp
				elif (i.start()==0 and not a[i.end()].isdigit()):
					a= temp + a[i.end():]
				elif (i.end()==len(a) and not a[i.start()-1].isdigit()):
					a = a[:i.start()] + temp 
				elif (not a[i.start()-1].isdigit() and not a[i.end()].isdigit()):
					a = a[:i.start()] + temp + a[i.end():]
				counter = i.end()
			#print a
	return a  

#Function to Octal Encode. Only digits present in the message are converted to Octal. 
def OctEnc(a):
	for ele in re.findall("[\d]+(?:,\d\d\d)*?", a):
		temp=oct(int(ele))
		temp = temp[1:]
		for i in re.finditer(ele,a):
			length= len(ele)
			#print i.start()
			#print i.end()
			if (i.start()==0 and i.end()==len(a)):
				a=temp
			elif (i.start()==0 and not a[i.end()].isdigit()):
				a= temp + a[i.end():]
			elif (i.end()==len(a) and not a[i.start()-1].isdigit()):
				a = a[:i.start()] + temp 
			elif (not a[i.start()-1].isdigit() and not a[i.end()].isdigit()):
				a = a[:i.start()] + temp + a[i.end():]
			#print a
	return a

#Function to Octal Encode. Only digits present in the message are converted to Octal. 
def OctDec(a):
	for ele in re.findall("[\d]+(?:,\d\d\d)*?", a):
		temp=str(int(ele,8)) 
		for i in re.finditer(ele,a):
			length= len(ele)
			#print i.start()
			#print i.end()
			if (i.start()==0 and i.end()==len(a)):
				a=temp
			elif (i.start()==0 and not a[i.end()].isdigit()):
				a= temp + a[i.end():]
			elif (i.end()==len(a) and not a[i.start()-1].isdigit()):
				a = a[:i.start()] + temp 
			elif (not a[i.start()-1].isdigit() and not a[i.end()].isdigit()):
				a = a[:i.start()] + temp + a[i.end():]
			#print a
	return a

#Function to Hex Encode. Only digits present in the message are converted to Hex.
def HexEnc(a):
	for ele in re.findall("[\d]+(?:,\d\d\d)*?", a):
		temp=hex(int(ele)).split('x')[1]
		#print temp
		for i in re.finditer(ele,a):
			length= len(ele)
			#print i.start()
			#print i.end()
			if (i.start()==0 and i.end()==len(a)):
				a=temp
			elif (i.start()==0 and not a[i.end()].isdigit()):
				a= temp + a[i.end():]
			elif (i.end()==len(a) and not a[i.start()-1].isdigit()):
				a = a[:i.start()] + temp 
			elif (not a[i.start()-1].isdigit() and not a[i.end()].isdigit()):
				a = a[:i.start()] + temp + a[i.end():]
			#print a
	return a 

def HexDec(a):
	for ele in re.findall("[\d]+(?:,\d\d\d)*?", a):
		temp=str(int(ele,16))
		#print temp
		for i in re.finditer(ele,a):
			length= len(ele)
			#print i.start()
			#print i.end()
			if (i.start()==0 and i.end()==len(a)):
				a=temp
			elif (i.start()==0 and not a[i.end()].isdigit()):
				a= temp + a[i.end():]
			elif (i.end()==len(a) and not a[i.start()-1].isdigit()):
				a = a[:i.start()] + temp 
			elif (not a[i.start()-1].isdigit() and not a[i.end()].isdigit()):
				a = a[:i.start()] + temp + a[i.end():]
			#print a
	return a 

#Testing
# a="My name is aasthae+1010 \ p t . = ppp10"
# print BinDec(a)

