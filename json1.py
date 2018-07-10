import sys
import base64
sys.path.insert(0, './Modules')
import enc_dec_aes

def extract_dic(a):
    global b 
    b =  ""
    global stack
    stack = []
    global i
    i=0
    print "length of a" +str(len(a))
    while (i<len(a)):
    	print a[i]
        # if (a[i]=='{' and (i+1)!=len(a) and (a[i+1] == '\'' or a[i+1] == '\"')):
        #     b = b+ a[i]
        #     print "In if block { 1"
        #     print i
        #     if (stack.count('{')!=0):
        #     	print "In if block { 2"
        #     	print i
        #     	print "while loop starting:"
        #         count =1
        #         i =i +1
        #         stack.append('{')
        #         stack.append('\"')
        #         while count!=0:
        #             if (a[i] == '{' and (i+1)!=len(a) and (a[i+1] == '\'' or a[i+1] == '\"')):
        #                 print "In if block { 3"
        #                 print i
        #                 b = b + a[i]
        #                 count = count +1
        #                 stack.append('{')
        #             elif (a[i]== '\"'):
        #                 b = b + '\''
        #             elif (a[i] == '}' ):
        #                 b = b + a[i]
        #                 stack.pop(len(stack)-1)
        #                 stack.pop(len(stack) -1)
        #                 count  = count -1
        #             else:
        #                 b = b + a[i]
        #             i =i+1
        #             print b
        #             print i
        #         i = i-1
        #         print "while loop ends"

        #     else:
        #         stack.append(a[i])
        #         stack.append('\"')
        if ((a[i] == '\"' or a[i] == '\'') and (a[i-1] == '{' or a[i-1] == ',')):
        	i=i+1
        	c = ""
        	while ((a[i] != '\"' and a[i] != '\'') and (a[i+1] != '}' and a[i+1] != ':')):
        		c = c + a[i]
        		print "c is " +c 
        		i = i +1
        	b = b + a[i] + c + a[i] +a[i+1]
        	i = i + 1
        	print "Word"
        	print b
        	if (c in para):
        		
        		#print "i is" + str(i)
        		temp = ""
        		print "i is" + str(i) + "a[i] " +a[i]
        		print "hi"
        		flag =0
        		i =i +1
        		if (a[i] == '\"' or a[i] == '\''):
        			flag=1 
        			i = i + 1
        			print "i is" + str(i) + "a[i] " +a[i]
        			stack.append(a[i])
        		
        		while (1):
        			print "temp" + temp
        			print "stack" +str(stack)
        			if (a[i] == '}'  and (stack.count('\"')==0 and stack.count('\'') == 0 )):
        				break;
        			# elif (a[i] == ',' and (stack.count('\"')!=0 and stack.count('\'') != 0 ) )
        			if (a[i] == '{'):
        				print "inner loop"
        				while (1):
        					if (a[i]=='}' and (a[i+1]=='\"' or a[i+1]=='\'')):
        						break;
        					temp = temp + a[i]
        					i =i +1
        				temp = temp + a[i]
        				print "Inner" + temp
        				print "i: " +str(i) + "a[i]" + a[i]
        			elif ((a[i] == '\'' or a[i]=='\"')):
        				if (stack.count('\'')==0 and stack.count('\"')==0 ):
        					stack.append(a[i])
        				else:
        					stack.pop(0)
        			else:
        				temp = temp +a[i] 
        			print "Secondd print: " + temp
        			i =i +1
        			print "i: " +str(i) + "a[i]" + a[i]
        		print temp
        		# if (flag ==1):
        		# 	if (a[i-1]== '\'' or a[i-1] == '\"'):
        		# 		temp1 = temp[:-1]
        		# 		print temp1
        		# 		temp1 = enc_dec_aes.aes_cbc_enc(key,temp1,iv,mode)
        		# 	else: 
        		# 		temp = enc_dec_aes.aes_cbc_enc(key,temp,iv,mode)
        		# 	b = b + a[i-1] + temp1 + a[i-1] +a[i]
        		# 	print b
        		# else: 
        		# 	temp = enc_dec_aes.aes_cbc_enc(key,temp,iv,mode)
        		# 	b = b+temp +a[i]

        # elif (a[i]=='}' and (a[i-1] =='\'' or a[i-1] == '\"')):
        #     b = b + a[i]
        #     stack.pop(len(stack)-1)
        #     stack.pop(len(stack)-1)
        else:
            b = b + a[i]
        i = i +1
        print b 
        print " asff i: " +str(i) 
    return b

iv = base64.b64encode("EDJ90vaiCSWtUPX6x/bFAQ==")
key = "441538f57b510c0512f594c213cc523c"
mode = "CBC"
para = ['Request']
a ="{\"Request\":\"{\"UserID\":{{{{{{\"4760\",\"Password\":\"pass@4760\",\"LoginType\":0}\"}"
print extract_dic(a)