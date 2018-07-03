# -*- coding: utf-8 -*-
import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser
import enc_dec_aes
import enco_deco
import base64
from termcolor import colored
import traceback


def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)

def join_with_script_dir(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = join_with_script_dir('ca.key')
    cacert = join_with_script_dir('ca.crt')
    certkey = join_with_script_dir('cert.key')
    certdir = join_with_script_dir('certs/')
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)

        with self.lock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        if self.path == 'http://proxy2.test/':
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()
            
            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            # support streaming
            if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
                self.response_handler(res,res_body)
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(res)
                with self.lock:
                    self.save_handler(req, req_body, res, '')
                return

            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            #res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            if "Content-Length" not in line:
                self.wfile.write(line)
        #if res_body_modified is not None:
        self.wfile.write("Content-Length: "+str(len(res_body))+"\r\n")
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        print with_color(33, req_header_text)

        u = urlparse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            print with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text)

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print with_color(32, "==== COOKIE ====\n%s\n" % cookie)

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print with_color(31, "==== BASIC AUTH ====\n%s\n" % token)

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                print with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text)

        print with_color(36, res_header_text)

        cookies = res.headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            print with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies)

        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    print with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                print with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text)


    def get_res_body_text(self,res,res_body):
        typ=0
        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str=json.dumps(json_obj,indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
                typ=1
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    print with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
                typ=0
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body
                typ=2
        return res_body_text,typ

    def request_handler(self, req, req_body):
        pass

    #This function will return the name of decrypting function to be called and the block size.
    def get_decryption_function(self):

            print colored("Enter Decryption Mode. Possible modes are Aes/Des/Des3-(ECB,CBC,CFB). Input Example- aes_cbc","green")
            dmode=raw_input()
            
            #Setting Block Mode from input
            block=16 if "aes" in dmode else 8
            
            #Forming decryption function name from input
            dmode=dmode+"_dec"
            decryption_final="enc_dec_"+dmode.split("_")[0]+'.'+dmode
            
            return decryption_final,block

    def get_decryption_key(self):

            print colored("Enter Decryption Key","green")
            dkey=raw_input()
            return dkey

    def get_padding_mode(self):

            print colored("Enter Padding Mode.(Bit,CMS,ZeroLen,Null,ISO,Random). See comments for explanation.","green")
            # MODES ={
            # (0,'Bit')     : 'BitPadding: Pad with 0x80 (10000000) followed by zero (null) bytes. Described in ANSI X.923 and ISO/IEC 9797-1',
            # (1,'CMS')     : 'Also called PKCS#5/PKCS#7. Pad with bytes all of the same value as the number of padding bytes. Default mode used in Cryptographic Message Syntax (CMS as defined in RFC 5652, PKCS#5, PKCS#7 and RFC 1423 PEM)',
            # (2,'ZeroLen') : 'Also called ANSI X.923. Pad with zeroes except make the last byte equal to the number (length) of padding bytes',
            # (3,'Null')    : 'Also called Zero Padding.Pad with null bytes. Only for encrypting of text data.',
            # (4,'ISO')   : 'Known as ISO/IEC 7816-4. Pad with 80 (Hexadecimal) followed by 00.Identical to the bit padding scheme.',
            # (5,'Random')  : 'Also called -ISO 10126. Pad with random bytes + last byte equal to the number of padding bytes'         
            # }
            mode=raw_input()
            return mode

    def get_encoding_type(self):

            print colored("Enter Encoding type.(Base64Dec/AsciiHexDec/BinDec/OctDec/HexDec)","green")
            dencod=raw_input()
            #Forming Decoding Fucnction. dencod is the final function to be called for decoding.
            dencod="enco_deco."+dencod
            return dencod

    def get_iv_info(self,decryption_final,block):

        iv_info=None
        if "ecb" not in decryption_final:
                #Asking for IV input as mode is not ECB
                print colored("Is IV appended with ciphertext? (y or n)","green")
                iv_check=raw_input()
                iv_info=raw_input("Enter whether IV is appended at beginning or at end, IV length is "+str(block)+".\nEnter beg/end\n") if iv_check == 'y' else raw_input("Enter decoded IV")
        return iv_info


    #This function will be called if reponse is of json type
    def response_is_json(self,res,res_body):

            #The response is of Json Type, so now we will ask for required parameters.
            print colored("The response is of json/dictionary\n","green")
            body=json.loads(res_body)
            print(body)

            print colored("\nPress 0 for decrypting entire body (keys+values)? \nPress 1 for decrypting only values.\nPress 2 for exit","green")
            decision=raw_input()
            if decision=='2':
                os._exit(1)
                quit()

            decryption_info=self.get_decryption_function()
            decryption_final=decryption_info[0]
            block=decryption_info[1]

            dkey=self.get_decryption_key()
            
            mode=self.get_padding_mode()
            
            dencod=self.get_encoding_type()

            #Asking for function specific parameters. No IV for ECB and Segment Size for CFB.      
            iv_info=self.get_iv_info(decryption_final,block)
            #Segment size will only be asked if CFB Mode is there
            seg_size=raw_input("Enter Segment Size. Must be iv_info multiple of 8. If left blank, then 8 will be taken by default") if "cfb" in decryption_final else None
         
            #Decryption Starts here based on choices entered before.
            if decision=='0':    
            #Entire Response Body (Keys and Values) will be decrypted now.
            #ct= Actual Data to be decrypted
            #iv= IV
                
                for key, value in body.iteritems():
                    #ct= Actual Data to be decrypted
                    #iv= IV

                    #Decrypting all keys
                    decoded_key=eval(dencod)(key)
                    if iv_info is not None:
                        if iv_info=='beg' or iv_info== 'end':
                            #Extracting IV from Cipher Text
                            iv=decoded_key[0:block] if iv_info=='beg' else decoded_key[-block:]
                            ct=decoded_key[16:] if iv_info =='beg' else decoded_key[0:len(decoded_key)-block]
                        else: 
                            iv=iv_info
                            #Assuming entire decoded data is to be decrypted here.
                            ct=decoded_key

                        key=eval(decryption_final)(dkey,ct,iv,mode) if seg_size == None else eval(decryption_final)(dkey,ct,iv,mode,seg_size)
                    
                    else:
                        #If this is called, then no IV was required. Meaning most probably ECB Mode.                           
                        key=eval(decryption_final)(dkey,decoded_key,mode)


                    #Decrypting all values                        
                    decoded_value=eval(dencod)(value)
                    if iv_info is not None:
                        if iv_info=='beg' or iv_info=='end':
                            #Extracting IV from Cipher Text
                            iv=decoded_value[0:block] if iv_info=='beg' else decoded_value[-block:]
                            ct=decoded_value[16:] if iv_info =='beg' else decoded_value[0:len(decoded_value)-block]
                        else: 
                            iv=iv_info
                            ct=decoded_value

                        value=eval(decryption_final)(dkey,ct,iv,mode) if seg_size == None else eval(decryption_final)(dkey,ct,iv,mode,seg_size)
                    
                    else:
                        #If this is called, then no IV was required. Meaning most probably ECB Mode.
                        value=eval(decryption_final)(dkey,decoded_value,mode)


                res_body_text=body

            else:

            #Only values will be decrypted
                print colored("Decrypt all values(y/n)?","green")  
                ans=raw_input()
                
                if ans=='y':
                #Decrypting all values
                    for key in body:
                        decoded_value=eval(dencod)(body[key])
                        
                        if iv_info is not None:
                            if iv_info=='beg' or iv_info=='end':
                                #Extracting IV from Cipher Text
                                iv=decoded_value[0:block] if iv_info=='beg' else decoded_value[-block:]
                                ct=decoded_value[16:] if iv_info =='beg' else decoded_value[0:len(decoded_value)-block]
                            else: 
                                iv=iv_info
                                ct=decoded_value

                            body[key]=eval(decryption_final)(dkey,ct,iv,mode) if seg_size == None else eval(decryption_final)(dkey,ct,iv,mode,seg_size)
                        
                        else:
                            #If this is called, then no IV was required. Meaning most probably ECB Mode.
                            body[key]=eval(decryption_final)(dkey,decoded_value,mode)
                
                else:
                    list_val=[]
                    print colored("Enter all keys whose values have to be decrypted","green")
                    list_val.append(raw_input())
                    #Here only specific values will be encrypted.
                    
                    for i in list_val:
                        decoded_value=eval(dencod)(body[i])

                        if iv_info is not None:
                            if iv_info =='beg' or iv_info=='end':
                                #Extracting IV from Cipher Text
                                iv=decoded_value[0:block] if iv_info=='beg' else decoded_value[-block:]
                                ct=decoded_value[16:] if iv_info =='beg' else decoded_value[0:len(decoded_value)-block]

                            else: 
                                iv=iv_info
                                #Assuming entire decoded data is to be decrypted here.
                                ct=decoded_value
                            body[i]=eval(decryption_final)(dkey,ct,iv,mode) if seg_size == None else eval(decryption_final)(dkey,ct,iv,mode,seg_size)
                        
                        else:
                            #If this is called, then no IV was required. Meaning most probably ECB Mode.
                            body[i]=eval(decryption_final)(dkey,decoded_value,mode)



                res_body_text=body


            return json.dumps(res_body_text,indent=2).replace("\\\"","")


    def response_custom(self,res,res_body_text):
        #This function will handle non json type responses.
        print colored("\nThe Content Type is "+res.headers.get('Content-Type', ''),"green")
        file = open("response.txt","w")
        file.write(str(res_body_text))
        file.close() 
        print colored("The response is saved in a file- response.txt. Please see it and select words to decrypt.","green")
        print colored("You will have to enter the words in program to be decrypt them manually.","green")
        print colored("After you have decrypted the required words and made changes to txt file. Select Exit","green")
        print colored("Press 1 to start decryption. Press 2 to Exit")
        ext=raw_input()
        while ext==str(1):
            print colored("Do all words to be decrypted have same parameters- Decryption Function, Mode, Paddding. (y or n)","green")
            ans=raw_input()
            if ans=='y':
                decryption_info=self.get_decryption_function()
                decryption_final=decryption_info[0]
                block=decryption_info[1]
                    
                dkey=self.get_decryption_key()
                mode=self.get_padding_mode()
                dencod=self.get_encoding_type()
                while ext==str(1):
                    print colored("Enter word to be decrypted","green")
                    word=raw_input()
                    iv_info=self.get_iv_info(decryption_final,block)
                    seg_size=raw_input("Enter Segment Size. Must be iv_info multiple of 8. If left blank, then 8 will be taken by default") if "cfb" in decryption_final else None
                    decoded_value=eval(dencod)(word)
                    print(len(decoded_value))
                    if iv_info is not None:
                        if iv_info=='beg' or iv_info=='end':
                            #Extracting IV from Cipher Text
                            iv=decoded_value[0:block] if iv_info=='beg' else decoded_value[-block:]
                            ct=decoded_value[16:] if iv_info =='beg' else decoded_value[0:len(decoded_value)-block]
                            print(len(iv))
                            print(len(ct))
                        else: 
                            iv=iv_info
                            ct=decoded_value
                        value=eval(decryption_final)(dkey,ct,iv,mode) if seg_size == None else eval(decryption_final)(dkey,ct,iv,mode,seg_size)
                    
                    else:
                        #If this is called, then no IV was required. Meaning most probably ECB Mode.
                        value=eval(decryption_final)(dkey,decoded_value,mode)
                    print colored("Decrypted value is"+value,"green")
                    print colored("1) Decrypt more words\n 2) Exit")
                    ext=raw_input()
                if ext=='2':
                    break
            else:
                while ext=='1':
                    print colored("Enter word to be decrypted","green")
                    word=raw_input()
                    decryption_info=self.get_decryption_function()
                    decryption_final=decryption_info[0]
                    block=decryption_info[1]
                    
                    dkey=self.get_decryption_key()
                    mode=self.get_padding_mode()
                    dencod=self.get_encoding_type()
                    iv_info=self.get_iv_info(decryption_final,block)
                    seg_size=raw_input("Enter Segment Size. Must be iv_info multiple of 8. If left blank, then 8 will be taken by default") if "cfb" in decryption_final else None
                    decoded_value=eval(dencod)(word)
                    if iv_info is not None:
                        if iv_info=='beg' or iv_info=='end':
                            #Extracting IV from Cipher Text
                            iv=decoded_value[0:block] if iv_info=='beg' else decoded_value[-block:]
                            ct=decoded_value[16:] if iv_info =='beg' else decoded_value[0:len(decoded_value)-block]
                        else: 
                            iv=iv_info
                            ct=decoded_value
                        value=eval(decryption_final)(dkey,ct,iv,mode) if seg_size == None else eval(decryption_final)(dkey,ct,iv,mode,seg_size)
                    
                    else:
                        #If this is called, then no IV was required. Meaning most probably ECB Mode.
                        value=eval(decryption_final)(dkey,decoded_value,mode)
                    print colored("Decrypted value is"+value,"green")
                    print colored("1) Decrypt more words\n2) Exit","green")
                    ext=raw_input()
                if ext=='2':
                    break
        print("Please save all changes in response.txt. Press 3 when done")
        final=raw_input()
        if final=='3':
            file=open("response.txt","r")
            res_body_text=file.read()

        return res_body_text



    def response_handler(self, res ,res_body):

        #key="441538f57b510c0512f594c213cc523c"
        #This function fetches response body and type. Type= 0 For html, 1 for json, 2 for others(text/)
        response_list=self.get_res_body_text(res,res_body)
        res_body_text=response_list[0]
        type_res=response_list[1]
        print("\n-------------------------------------------------")
        print colored("The response is printed below-",'green')
        print(res_body_text)
        print("")
        
        if type_res==1:
            #Handling Json Responses
            res_body_text=self.response_is_json(res,res_body_text)
        else:
            #Handling Other Responses
            res_body_text=self.response_custom(res,res_body_text)
        return res_body_text




    def save_handler(self, req, req_body, res, res_body):
        self.print_info(req, req_body, res, res_body)



def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 6666
    server_address = ('::1', port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()


if __name__ == '__main__':
    test()
