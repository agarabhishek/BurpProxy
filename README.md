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
`pip -r requirements.txt`  

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

	1) AES `AES`
	2) DES  `DES`
	3) DES3 `DES3`

*Files are named as- enc_dec_[method].py Example- enc_dec_aes.py,enc_dec_des.py*

Currently Supported Encoding Schemes:

	1) Base64 `Base64`
	2) URL Encoding `URL`
	3) AsciiHex `AsciiHex`
	4) Binary `Bin`
	4) Octal `Oct`
	4) Hexadecimal `Hex` 

*File is EncDec.py*

Currently Supported Padding Schemes:

	1) BitPadding: Pad with 0x80 (10000000) followed by zero (null) bytes.
	2) CMS: Also called PKCS#5/PKCS#7. Pad with bytes all of the same value as the number of padding.
	3) ZeroLen: Also called ANSI X.923. Pad with zeroes except make the last byte equal to the number (length) of padding bytes.
	4) Null: Also called Zero Padding.Pad with null bytes. Only for encrypting of text data.
	5) ISO: Known as ISO/IEC 7816-4. Pad with 80 (Hexadecimal) followed by 00.
	6) Random: Also called -ISO 10126. Pad with random bytes + last byte equal to the number of padding bytes. 
	
*File is Padding.py*
*See README in Padding.tar.gz for more details*


##**VI) Further Changes**

Below are some guidelines to add new encryption,padding or encoding modules-

**Encryption**

Each encryption scheme has its own file inside Modules folder.
So,create a new file as enc_dec_[scheme].py
Corresponsing to each mode (ECB/CBC etc) there are two functions (encryption and decryption) named as follows
[scheme]\_[mode]\_[enc](arguments) for encryption
[scheme]\_[mode]\_[dec](arguments) for decryption










