import os
files=['iv.txt','requirements.dat','multiple.txt','reqpara.txt','respara.txt']
for i in files:
	if os.path.isfile(i):
		os.remove(i)
