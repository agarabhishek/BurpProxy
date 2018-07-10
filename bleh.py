	
	
def extract_dic(self,a):
	global b 
	b =  ""
	global stack
	stack = []
	global i
	i=0
	while (i<len(a)):
		if (a[i]=='{'):
			b = b+ a[i]
			if (stack.count('{')!=0):
				count =1
				i =i +1
				stack.append('{')
				while count!=0:
					if a[i] == '{':
						b = b + a[i]
						count = count +1
						stack.append('{')
					elif (a[i]== '\"'):
						b = b + '\''
					elif (a[i] == '}'):
						b = b + a[i]
						stack.pop(len(stack)-1)
						count  = count -1
					else:
						b = b + a[i]
					i =i+1
				i = i-1
			else:
				stack.append(a[i])
		elif (a[i]=='}'):
			b = b + a[i]
			stack.pop(len(stack)-1)
		else:
			b = b + a[i]
		i = i +1
	return b