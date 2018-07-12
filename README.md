#**Python Proxy**

##**I) Introduction**

This proxy aims to work as a Burp Extender. It is used for Encrypting/Decrypting Traffic.
Many clients send and recieve encrypted traffic to and from server.
Our proxy aims to reduce the manual work of decrypting and encrypting the traffic required at Burp. 

##**II)Typical Usage**
*
C: Client  
P: Proxy  
B: Burp  
S: Server  
*
  
*Without Proxy:*  


  **C** ------*Encrypted Traffic*------- **B (Decrypt Traffic -> Fuzz -> Encrypt Traffic)** ---------*Encrypted Traffic*--------- **S**

*With proxy:*  


  **C** -----*Encrypted Traffic*-----**P (Decrypt Traffic)**---*Decrypted Traffic*--- **B (Fuzzing)** ---*Decrypted Traffic*---**P (Encrypt Traffic)**-----*Encrypted Traffic*---- **S**

					

Hence, two instances of same file will run.

##**III) Setup**

Run the following commands  
  
`./setup.sh`   
`pip install ./Padding.tar.gz`  
`pip requirements.txt`  

Note- Python 2.7 required.

##**IV) Usage**

Proxy Instance 1- P1  
Proxy Instance 2- P2  

**_Start P1_**  
  
`python proxy.py [Port] [Cipher Method] [Key] [Cipher Mode] [Encoding Mode] [Choice] [e/d] [Padding Mode] [Position of IV] [Log Level] [Segment Size]`  
  
Example: `python proxy.py 6666 AES 441538f57b510c0512f594c213cc523c CBC Base64 3 d CMS 1 2`  
  
**_Start P2_**  
  
`python proxy.py [Port]`  

Example: `python proxy.py 5555`

 
######*Arguments*  

Cipher Method - AES/DES/DES3 etc.  

Cipher Mode - CBC/ECB/CFB etc  

Encoding Mode - Base64/Hex/Oct etc  

Choice-  

	1)Encrypt/Decrypt Enitre body.  
	2)Encrypt/Decrypt all values.  
	3)Encrypt/Decrypt selected values.  


'e' if this script is P2, 'd' is this is P1  

Padding Mode - CMS/Bit/ISO etc  

Position of IV : 1 for Starting, 2 for Ending  

Log Level- 0/1/2. Proxy 1 writes to p1.txt and Proxy 2 writes to p2.txt  

       	0- No Logs 
	1- Only prints what is modified in the script.     
	2- Prints everything.  

Segment Size= Only in CFB mode, must be multiple of 8. If left blank, 8 will be taken by default.

##**V) Current Support**

Currently Supported Encryption Methods:


