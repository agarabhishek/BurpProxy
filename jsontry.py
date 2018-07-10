import sys
import base64
sys.path.insert(0, './Modules')
import enc_dec_aes
import json


baseStr = '{"Request":"{"UserID":}:""}""}:},""4760","Password":"pass@4760....???\"""":;;,,,,535436364:","LoginType":0}",\"Aastha\":\"I am awesome\"}'
dic = json.loads("{\"Request\":\"{'UserID':'4760','Password':'pass@4760','LoginType':0}\",\"Aastha\":\"I am awesome\"}")

def getKey(start,baseStr):
	i = start
	while i<len(baseStr):
		if baseStr[i] == ':':
			j = i - 2
			b = []
			while baseStr[j]!='\'' and baseStr[j]!= '\"':
				b.append(baseStr[j])
				j = j-1
			b.reverse()
			a =""
			for j in range(len(b)):
				a = a +b[j]
			return i,a
		i =i + 1
	return i, None

def checkKey(start, baseStr):
	flag = 0
	if baseStr[start] == '\'' or baseStr[start] == '\"':
		flag =1
	i =start
	while i<len(baseStr):
		if baseStr[i] == ':':
			b = []
			if flag == 1:
				a = frameStr1(start,baseStr, i)
			else:
				a = frameStr2(start,baseStr, i)
			return start,a
		i = i + 1

def frameStr1(start,baseStr,i):
	k = i - 2
	b = []
	while k>start:
		b.append(baseStr[k])
		k = k - 1
	b.reverse()
	a = ""
	for j in range(len(b)):
		a = a +b[j]
	return a

def frameStr2(start,baseStr,i):
	k = i -1
	b = []
	while k>=start:
		b.append(baseStr[k])
		k = k - 1
	b.reverse()
	a = ""
	for j in range(len(b)):
		a = a +b[j]
	return a

def getVal(start,baseStr):
	val = []
	flag = 0
	if (baseStr[start] == '\'' or baseStr[start] == '\"'):
		flag = 1
	i = start
	while i<len(baseStr):
		if baseStr[i] == ',':
			k , a = checkKey(i+1,baseStr)
			if str(a) in dic.keys():
				if flag == 1:
					a = frameStr1(start,baseStr, i)
				else:
					a = frameStr2(start,baseStr, i)
				return i,a

		elif baseStr[i] == '}':
			if i == len(baseStr)-1:
				if flag == 1:
					a = frameStr1(start,baseStr, i)
				else:
					a = frameStr2(start,baseStr, i)
				return i,a
		i = i + 1

iv = base64.b64decode("EDJ90vaiCSWtUPX6x/bFAQ==")
key = "441538f57b510c0512f594c213cc523c"
mode = "CMS"
para = ['Request','Aastha']
it = 0
result = baseStr

while it<len(baseStr):
	a= ""
	it, a =getKey(it,baseStr)
	b= ""
	if a is not None:
		it, b = getVal(it+1,baseStr)
		if a in para:
			temp = b
			temp = enc_dec_aes.aes_cbc_enc(key,temp,iv,mode)
			temp = base64.b64encode(temp)
			result = result.replace(str(b),str(temp))

print result
