a=[1,2,3]
file=open("testplain.txt","w")
for i in a:
    file.write(str(i)+"\n")
file.close()
file=open("testplain.txt","r")
a=file.readlines()
print(a[0].replace("\n",""))
file.close()