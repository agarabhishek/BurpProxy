import os
files=['iv.txt','requirements.dat','multiple.txt','reqpara.txt','respara.txt','reqjson.txt','resjson.txt','temp.txt','p1.txt','p2.txt']
for i in files:
	if os.path.isfile(i):
		os.remove(i)
