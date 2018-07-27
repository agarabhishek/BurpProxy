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
`pip install -r requirements.txt`  

Note- Python 2.7 required.

##**IV) Usage**

Proxy Instance 1- P1  
Proxy Instance 2- P2  

**Open proxy.py and change the ip address with your machine's ip. (server_address in test(),Line no-1150)**  
  
**_Start P1_**  
  
`python proxy.py [Port] [Cipher Method] [Key] [Cipher Mode] [Encoding Mode] [Choice] [e/d] [Padding Mode] [Position of IV] [Log Level] [Segment Size]`  
  
Example: `python proxy.py 6666 AES sdfsds5453dfsff CBC Base64 3 d CMS 1 2`  
  
**_Start P2_**  
  
`python proxy.py [Port]`  

*Once you start P1, you don't need to input the command line arguments again while starting P2 as the arguments are stored by P1 in a file and P2 reads from it.*     

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
	e stands for encryption and d stands for decryption. So if you enter 'e' first, then the script is assumed to be P2 as it will do encryption first. If you enter 'd' then the script becomes P1 as it will do decryption first.  

Padding Mode - CMS/Bit/ISO etc  

Position of IV : 1 for Starting, 2 for Ending , 3 if IV is not appended  
	This signifies the position at which IV is appended before cipher text is sent from client to server or vice-versa.      
	If for some case, the IV is not randomly generated but is hardcoded and same on both client and server then on the next prompt "Want to Enter IV (y/n)?". Enter "y" and then input the IV.   
	In this case, IV is not sent with request/response.     

Log Level- 0/1/2. Proxy 1 writes to p1.txt and Proxy 2 writes to p2.txt  

       	0- No Logs 
		1- Only prints what is modified in the script.     
		2- Prints everything.  

Segment Size= Only in CFB mode, must be multiple of 8. If left blank, 8 will be taken by default.

##**V) Current Support**  

**Currently Supported Content Types:**

*In content types which have key-value pairs, we can encrypt-decrypt all values or multiple values.*

        1) text/plain: Encrypt/Decrypt Entire Body
        2) text/html:  Encrypt/Decrypt Entire Body
        3) text/xml: Encrypt/Decrypt Entire Body
        4) application/json : Has Key-Value pairs. 
        5) application/xml: Has Key-Value pairs. 
        6) application/x-www-form-urlencoded: Has Key-Value pairs. 
        7) multipart/form-data: Has Key-Value pairs.
        8) application/xhtml+xmls: Has Key-Value pairs.

**Currently Supported Encryption Methods:**

	1) AES - Advanced Encryption Standard
	2) DES - Data Encryption Standard
	3) DES3 - Triple DES

*Files are named as- enc_dec_[method].py Example- enc_dec_aes.py,enc_dec_des.py*

**Currently Supported Encoding Schemes:**

	1) Base64 - Base64
	2) URL - URL Encoding
	3) AsciiHex - AscII Hexadecimal
	4) Bin - Binary
	4) Oct - Octal
	4) Hex - Hexadecimal 

*File is EncDec.py*

**Currently Supported Padding Schemes:**

	1) BitPadding - Pad with 0x80 (10000000) followed by zero (null) bytes.
	2) CMS - Also called PKCS#5/PKCS#7. Pad with bytes all of the same value as the number of padding.
	3) ZeroLen - Also called ANSI X.923. Pad with zeroes except make the last byte equal to the number (length) of padding bytes.
	4) Null - Also called Zero Padding.Pad with null bytes. Only for encrypting of text data.
	5) ISO - Known as ISO/IEC 7816-4. Pad with 80 (Hexadecimal) followed by 00.
	6) Random - Also called -ISO 10126. Pad with random bytes + last byte equal to the number of padding bytes. 
	
*File is Padding.py*
*See README in Padding.tar.gz for more details*


##**VI) Further Changes**

Below are some guidelines to add new encryption,padding or encoding modules-

**Encryption**

Each encryption scheme has its own file inside Modules folder. 
So,create a new file as enc_dec_[scheme].py  
Inside the file,corresponsing to each mode (ECB/CBC etc) there are two functions named as follows-  

`def [scheme]_[mode]_[enc](arguments)` for encryption   
`def [scheme]_[mode]_[dec](arguments)` for decryption  

These functions return the plain text/cipher text.  
Example of a function is given below:    

	#Encryption for AES-CBC  
	def aes_ecb_enc(key,plain_txt,mode):   
		global blocksize  
		encryption_suite=AES.new(key,AES.MODE_EBC)  
		plain_txt_pad=appendPadding(plain_txt,blocksize=blocksize,mode=mode)  
		cph_txt=encryption_suite.encrypt(plain_txt_pad)  
		return cph_txt       
  
Arguments are - key,plain text,padding mode, iv, segment_size (only for CFB)  
  
    
**Encoding**  
  
There is a single file for Encoding schemes- EncDec.py inside Modules Folder.  
We have tried to cover all possible encodings. To add a new scheme, you need to simply add two functions as follows-  

`def [scheme]Enc(argument)` for encoding  
`def [scheme]Dec(argument)` for decoding  

These functions return the encoded/decoded text.   
Example of a function is given below:  

	def Base64Dec(msg):  
		return base64.b64decode(msg)

Argument is simply the text to be encoded/decoded.  

  
**Padding**

There is a single file for Padding schemes- Padding.py inside Padding.tar.gz.
We have tried to cover all possible paddings. To add a new padding scheme, you need to simply add two functions as follows-  

`def append[scheme]Padding(arguments)`  for appending  
`def remove[scheme]Padding(arguments)`  for removing    

These functions return the modified text.  
Example of a function is given below:  

	def removeISOPadding(str, blocksize=AES_blocksize):     
	    pad_len = 0          
	    for char in str[::-1]: # str[::-1] reverses string  
	        if char == '\0':    
	            pad_len += 1    
	        else:    
	            break    
	    pad_len += 1    
	    str = str[:-pad_len]    
	   	return str     

Arguments are the text to be modified and blocksize.


##**VII) Extra**

* flush.py file can be used to delete temporary files which will be created while running the scripts. 
These files should be ideally flushed every time a new request is sent.

*  *Note: In multipart/form-data, suppose we have the following body-*  

		--------------------------d74496d66958873e
		Content-Disposition: form-data; name="person"    
		    
		akdbsakdbsj=sadaln
		--------------------------d74496d66958873e
		Content-Disposition: form-data; name="secret"; filename="file.txt"
		Content-Type: text/plain
		  
		sdakjldnd1213%^%r^eJDBSHALFDHLFVSHVSFVS
		--------------------------d74496d66958873e--
 
	If choice 2 is selected of decrypting all values then both the value of 'person' and 'file.txt' will be decrypted but in option 3, you will to write the text which you have to decrypt - 'akdbsakdbsj=sadaln'. But this will cause a problem at encryption end if fuzzing occurs.  
	Hence, implementation for choice 3 in multipart is not complete.    
  
*  If we have content types as plain or html, currently we can only encrypt/decrypt entire body.  
The functionality to decrypt/encrypt specific parts of the body is not implemented.  
