# -*- coding: utf-8 -*-
import sys
import os
import socket
import ssl
import select
import urlparse
import threading
import gzip
import zlib
import time
import httplib
import json
import re
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser
import base64
from pathlib import Path
from termcolor import colored
import traceback
sys.path.insert(0, './Modules')
import enc_dec_aes
import enc_dec_des
import enc_dec_des3
import EncDec


def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)

def join_with_script_dir(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET
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

    # Function to establish the connection, send certificates.
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

    # Function to send data, if certificates are not found. Interception does not take place.
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
    # Main Interceptor Function
    def do_GET(self):
        if self.path == 'http://proxy2.test/':
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None
        global flag_for_url
        global target

        # Set target for all requests from the first request. So that burp's fuzzing doesn't change target.
        if flag_for_url==0:
            target=req.headers['Host']
            flag_for_url=1

        # If this is P2(Proxy-2) meaning encrdecr == 'e', then request path contains protocol and host. Regex to remove it.
        req.path=re.sub("^.*//.*?/","/",req.path) if encrdecr == "e" else req.path
        
        # Creating a temporary url from which parameters will be fetched.
        if isinstance(self.connection, ssl.SSLSocket):
            temp_url = "https://%s%s" % (target, req.path)
        else:
            temp_url = "http://%s%s" % (target, req.path)

        # request_handler is the function which modifies the request body. Entire Encryption/Decryption takes place inside it.
        req_body_modified,req_body_original = self.request_handler(req, req_body)
        
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(temp_url)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))
        
        r"""
        Example-
        temp_url= https://www.xyz.com/abc/item?id=1
        scheme= https
        netloc = wwww.xyz.com
        path = /abc/item?id=1
        """

        # Connection is formed,request is sent and response is read.
        try: 
            origin = (scheme, netloc)
            if encrdecr=='d': # Proxy-1 (P1) has encrdecr=='d', So its traffic will go to Burp.
                self.tls.conns[origin] = httplib.HTTPConnection("localhost",3333) # Burp's Address
                # After setting the proxy, we set a tunnel to the actual server's domain.
                self.tls.conns[origin].set_tunnel(netloc) # netloc has server's address.
                conn = self.tls.conns[origin]
            else: # This happens if the file is P2. No proxy, directly send to server.
                self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
                conn = self.tls.conns[origin]

            # Now connection parameters are all set. 
            # conn.request forms a connection and sends the request
            conn.request(self.command,path,req_body, dict(req.headers))

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

            res_body = res.read() # Reading response

        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            # If connection not formed or request not sent, return Bad Gateway.
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        # reponse_handler functions modifies the response received. Entire Encryption/Decryption takes place inside it.
        res_body_modified,res_body_original = self.response_handler(res, res_body_plain)
        
        if res_body_modified is False:
            self.send_error(403)
            return
        
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            
        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            if "Content-Length" not in line:
                self.wfile.write(line)
        self.wfile.write("Content-Length: "+str(len(res_body))+"\r\n")
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain, req_body_original,res_body_original)

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

    # All method calls are proccessed as GET request calls.
    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    # Function to filter headers.
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

    #Function to encode message contents(gzip,x-gzip,deflate)
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

    #Function to decode message contents(gzip,x-gzip,deflate)
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

    #Function to print on both console and log file
    def print_info(self, req, req_body, res, res_body,req_body_original,res_body_original):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))
        
        #Request and Response header texts are combined
        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        #Request --
        print with_color(33, req_header_text)
        u = urlparse.urlsplit(req.path)
        #If Query parameters are present in the path-
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
                    json_str = json.dumps(json_obj)
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

        #Response - 
        print with_color(36, res_header_text)
        cookies = res.headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            print with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies)
            filePrint.write("==== SET-COOKIE ====\n%s\r\n" % cookies)

        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj)
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
            
            #LOG LEVELS available - 0,1,2. Proxy 1 writes to p1.txt and Proxy 2 writes to p2.txt
            #1: only prints what is modified in the script.
            #2: prints everything 
            if logslevel:
                filePrint = open('p1.txt','a+') if encrdecr == 'd' else open('p2.txt','a+')
                filePrint.write("-------------------------------------------------------------------------------------------\r")
                filePrint.write("-------------------------------------------------------------------------------------------\r")
                filePrint.write("\rREQUEST:\r\n")
                filePrint.write(req_header_text+"\r\n")
                if u.query:
                    filePrint.write("==== QUERY PARAMETERS ====\n%s\r\n" % query_text)
                if cookie:
                    filePrint.write("==== COOKIE ====\n%s\r\n" % cookie)
                if auth.lower().startswith('basic'):
                    filePrint.write("==== BASIC AUTH ====\n%s\r\n" % token)
                if logslevel == 1:
                    if encrdecr == 'd':
                        filePrint.write("==== REQUEST BODY ====\n%s\r\n" % req_body_text)
                    else:
                        filePrint.write("==== REQUEST BODY ====\n%s\r\n" % req_body_original)
                else:
                    filePrint.write("==== REQUEST BODY ORIGNAL ====\n%s\r\n" % req_body_original)                
                    filePrint.write("==== REQUEST BODY MODIFIED ====\n%s\r\n" % req_body_text)
                filePrint.write("\rRESPONSE:\r\r")
                filePrint.write(res_header_text+"\r\n")
                if cookies:
                    filePrint.write("==== COOKIE ====\n%s\r\n" % cookies)
                if logslevel == 1:
                    if encrdecr == 'd':
                        filePrint.write("==== RESPONSE BODY ====\n%s\r\n" % res_body_original)
                    else:
                        filePrint.write("==== RESPONSE BODY ====\n%s\r\n" % res_body_text)
                else:
                    filePrint.write("==== RESPONSE BODY ORIGINAL ====\n%s\r\n" % res_body_original)
                    filePrint.write("==== RESPONSE BODY MODIFIED ====\n%s\r\n" % res_body_text)
                filePrint.write("-------------------------------------------------------------------------------------------\r")
                filePrint.write("-------------------------------------------------------------------------------------------\r")
                filePrint.write("\r")
                filePrint.close()


# Encryption Block
# --------------------------------------------------------------------------------------------------------------------------------  

    #Function to extract IV
    def extractIV(self):
        iv = ""
        if ivf is None:
            ivobj = open('iv.txt', 'r') # Opened text file where iv was stored by decryption function.
            lines = ivobj.readlines()
            iv = lines[0] if encrdecr == 'e' else lines[1]
            ivobj.close()
        else:
            iv =ivf
        dec = "EncDec." + mode_enco + "Dec" # Forming Decoding Function
        iv = eval(dec)(iv) # Decoded iv stored.
        return iv

    #Function to append IV and encode the message.
    def appendIVEncode(self,temp,iv):
        if ivf is None and ivs == '1':
            temp = iv + temp
        elif ivf is None and ivs == '2':
            temp = temp + iv
        temp = eval(mode_encod)(temp)
        return temp

    #Function to extract text to encrypt.
    def getBodyEnc(self, requestString):
        return requestString

    #Function to encrypt entire body
    def encEntireBody(self,re_body,iv):
        re_body = self.encr(re_body,iv)
        re_body = self.appendIVEncode(re_body,iv)
        return re_body

# Helper Functions for proper encryption of json type ----------------------------------

    #Function to get next key in the message body
    #Function searches for ':' and takes the expression till '\'' or '\"' and returns the key
    def getKey(self,start,baseStr):
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

    #Function to check if the expression contains a key present in the message.
    #Function checks if the key starts with '\'' or '\"'. Extracts the next key till ':'. Sends positions to FrameStr* 
    #function which returns a string starting between the indexes sent. Function returns the key formed.
    def checkKey(self,start, baseStr):
        flag = 0
        if baseStr[start] == '\'' or baseStr[start] == '\"':
            flag =1
        i =start
        while i<len(baseStr):
            if baseStr[i] == ':':
                b = []
                if flag == 1:
                    a = self.frameStr1(start,baseStr, i)
                else:
                    a = self.frameStr2(start,baseStr, i)
                return start,a
            i = i + 1

    #Functions frameStr1/2 return the string between 2 indexes.
    def frameStr1(self,start,baseStr,i):
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

    def frameStr2(self,start,baseStr,i):
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

    #Function to obtain next value of the corresponding key found.
    #self.checkKey() returns the next key it finds. The key is checked in the dictionary 'dic'. If not present, ','
    #found is a part of the payload else, value ends. And frameStr() is called for forming the value.
    def getVal(self,start,baseStr,dic):
        val = []
        i = start + 1
        start = start + 1
        flag = 0
        while baseStr[i]==' ':   #Checks if there is space just after ':' in the value. Space is ignored for 
            i = i + 1            #processing
            start = start + 1
        if (baseStr[i] == '\'' or baseStr[i] == '\"'): #if value is a string, it starts with '\'' or '\"'
            flag = 1                                   #flag = 1. String and non string values call frameStr1 and
                                                       #frameStr2() respectively
        while i<len(baseStr):
            if baseStr[i] == ',':
                k , a = self.checkKey(i+1,baseStr)
                if str(a) in dic.keys():
                    if flag == 1:
                        a = self.frameStr1(start,baseStr, i)
                    else:
                        a = self.frameStr2(start,baseStr, i)
                    return i,a

            elif baseStr[i] == '}':
                if i == len(baseStr)-1:
                    k = i -1
                    while baseStr[k] == ' ' or baseStr[k] == '\n':
                        k = k -1
                    if flag == 1:
                        a = self.frameStr1(start,baseStr, k+1)
                    else:
                        a = self.frameStr2(start,baseStr, k+1)
                    return i,a
            i = i + 1

# Helper functions for json encryption end ---------------------------------------------

    #Function for processing json strings and encryption.
    #para: list of parameters whose value is to be encrypted.
    #dic: contains the base request keys and values for reference.
    def encr_json(self,re_body, iv,para,dic ):
        re_body_text = None
        try:
            baseStr = re_body
            it = 0
            result = baseStr
            print result
            while it<len(baseStr):
                a= ""
                it, a =self.getKey(it,baseStr)
                b= ""
                if a is not None:
                    it, b = self.getVal(it+1,baseStr,dic)
                    if a in para:
                        temp = b
                        temp = self.encr(temp,iv)
                        temp = self.appendIVEncode(temp,iv)
                        result = result.replace(str(b),str(temp))
            re_body_text  = result
        except Exception:
            re_body_text = re_body
            print (traceback.format_exc())
        return re_body_text

    #Function to encrypt XML message
    def encr_xml(self,re_body,iv,para):
        temp =""
        try:
            for i in para:
                i.replace('\n','')
            e = ET.fromstring(str(re_body))
            for elt in e.iter():
                if elt.tag in para and elt.text is not None:
                    elt.text=self.encr(elt.text,iv)
                    elt.text = self.appendIVEncode(elt.text,iv)
            #Check what to do about XML Version and encoding
            temp = ET.tostring(e, encoding='utf8', method='xml')
            
        except Exception:
            print (traceback.format_exc())
            temp  = re_body
        return temp

    #Function to encrypt www-urlencod
    def encr_www(self,re_body,iv,para):

        elem_dic=dict(x.split('=') for x in re_body.split("&"))
        for i in elem_dic:
            if elem_dic[i] in para:
                elem_dic[i]=self.encr(elem_dic[i],iv)
                elem_dic[i] = self.appendIVEncode(elem_dic[i],iv)
        temp = ""
        for key,value in elem_dic:
            temp = temp + key + '=' + value + '&'
        temp1 = temp [:-1]
        return temp1

    #Function to encrypt multipart form data
    #Reads lines from temp.txt and stores as a list in 'a'
    #Searches for boundary data. Then encrypts the data. 'lis' contains the final string.
    def encr_multi(self,re_body,iv,para,req_body):
        file=open("temp.txt","r")
        try:
            a=file.readlines()
            boundary=re_body
            lis=""
            i=0
            while i<len(a)-1:
                if boundary in a[i]:
                    lis=lis+a[i]
                    while a[i] != '\n':
                        lis=lis+a[i]
                        i=i+1
                    lis=lis+a[i]
                    i=i+1
                    temp=""
                    while boundary not in a[i]:
                        temp=temp+a[i]
                        i=i+1
                    if temp in parameters:
                        temp=temp[:-1]
                        temp=self.encr(temp,iv)
                        temp = self.appendIVEncode(temp,iv)
                        temp=temp+'\n'
                    lis=lis+temp
        except Exception:
            return req_body
        file.close()
        return lis
        
    #Encryption function. iv contains the extracted IV. 
    def encryption(self, re, re_body):
        try:
            iv = self.extractIV()
            re_body_text = None
            #Encryption of full request body:
            if (int(mxen)==1):
                re_body = getBodyEnc(re_body)
                re_body_text = encEntireBody(re_body,iv)

            #Encryption of Parameters: Encrypts all values only: 
            #filePara contains list of parameters whose values are to be encrypted.
            #fileDic contains the base JSON request. dic will read the key value pairs of the dictionary
            if (int(mxen)==2 or int(mxen) == 3):
                re_body = self.getBodyEnc(re_body)    #getBodyEnc returns the editted body if required.
                #returns content type of the request and boundary in case of multipart content type.
                re_body_text, content_type = self.get_body_text(re,re_body) 
                filePara = open('reqpara.txt','r') if encrdecr == 'e' else open('respara.txt','r')
                para = filePara.readlines()
                
                for i in range(len(para)):
                    para[i]=para[i].replace("\n","")
                if content_type == 1:
                    fileDic  = open('reqjson.txt','r') if encrdecr == 'e' else open('resjson.txt','r')
                    dic = json.loads(fileDic.read())
                    re_body_text = self.encr_json(re_body_text,iv,para,dic)
                    print self.encr_json(re_body_text,iv,para,dic)
                    fileDic.close()
                elif content_type == 3:
                    re_body_text = self.encr_xml(re_body_text,iv,para)
                elif content_type == 4:
                    re_body_text = self.encr_www(re_body_text,iv,para)
                elif content_type == 5:
                    re_body_text = self.encr_multi(re_body_text,iv,para,re_body) 
                elif content_type==0 or content_type==2:
                    print("We have not yet identified how to identify encrypted parameters in these content types")
                    re_body_text=re_body

                filePara.close()
        except Exception:
            return re_body
        return re_body_text

    # Calling Encryption Functions. 
    def encr(self, msg,iv):
        if (cipMethod=='AES'):
            if (cmode == 'ECB'):
                return enc_dec_aes.aes_ecb_enc(keyf, msg, padding)
            elif (cmode == 'CBC'):
                return enc_dec_aes.aes_cbc_enc(keyf, msg, iv, padding)
            elif (cmode == 'CFB'):
                return enc_dec_aes.aes_cfb_enc(keyf, msg, iv, padding, int(segment_size))

        if (cipMethod == 'DES'):
            if (cmode == 'ECB'):
                return enc_dec_des.des_ecb_enc(keyf, msg, padding)
            elif (cmode == 'CBC'):
                return enc_dec_des.des_cbc_enc(keyf, msg, iv, padding)
            elif (cmode == 'CFB'):
                return enc_dec_des.des_cfb_enc(keyf, msg, iv, padding, int(segment_size))

        if (cipMethod == 'DES3'):
            if (cmode == 'ECB'):
                return enc_dec_des3.des3_ecb_enc(keyf, msg, padding)
            elif (cmode == 'CBC'):
                return enc_dec_des3.des3_cbc_enc(keyf, msg, iv, padding)
            elif (cmode == 'CFB'):
               return enc_dec_des3.des3_cfb_enc(keyf, msg, iv, padding, int(segment_size)) 

# Encryption Block ends here ------------------------------------------------------------------------------------------------------

    #Request Handler--
    #If the proxy is P1 i.e. 'encrdecr' is 'd', decryption takes place. Else, encryption takes place (P2).
    def request_handler(self, req, req_body):
        global flag_side
        if encrdecr == 'e':
            flag_side=1
            return self.encryption(req,req_body),req_body
        else:
            flag_side=0
            print colored("The Request from Client-","green")
            print colored(req_body,"green")
            return self.decrypt(req,req_body),req_body


    def get_body_text(self,re,re_body):
    # This function returns the content type and extracts the body in a suitable form, if required.

        r"""Content type handled: 
        -text/plain
        -text/html,
        -text/xml,
        -application/json, 
        -application/xml, 
        -application/x-www-form-urlencoded,
        -multipart/form-data,
        -application/xhtml+xmls
        """
        
        con_type=0
        if re_body is not None:
            re_body_text=None
            content_type=re.headers.get('Content-Type','')

            if content_type.lower().startswith('application/json'):
                re_body_text=re_body
                con_type=1

            elif not (content_type.lower().startswith('application') or content_type.lower().startswith('text/xml')):
                re_body_text=re_body
                con_type=2

            elif content_type.lower().startswith('application/x') or content_type.lower().startswith('text/xml'):
                re_body_text=re_body
                con_type=3

            elif content_type.lower().startswith('application/x-www-form-urlencoded'):
                re_body_text=re_body
                con_type=4
            elif content_type.lower().startswith('multipart/form-data'):
                # In this case, boundary value is returned instead of body.
                con_type_header=re.headers.get('Content-Type', '')
                re_body_text=con_type_header.split("=")[1]
                con_type=5
            else:
                re_body_text=re_body
                con_type=0
        else:
            re_body_text = None        
        return re_body_text,con_type

# Decryption Block Starts here ----------------------------------------------------------------------------------------------------

    def response_handler(self, res ,res_body):
        #Modifies the response recieved by server.
        #key="441538f57b510c0512f594c213cc523c"
        global encrdecr
        if encrdecr=='e':
            print colored("The Response From Server-","green")
            print colored(res_body,"green")
            res_body_text=self.decrypt(res,res_body)
        else:
            res_body_text=self.encryption(res,res_body)
        return res_body_text,res_body

    def decrypt(self,re,re_body):
        
        # Get content body and content type
        re_list=self.get_body_text(re,re_body)
        re_body_text=re_list[0]
        con_type=re_list[1]

        global cipMethod
        global cmode
        global keyf
        global mode_enco
        global mode_encod
        global padding
        global ivs
        global ivf
        global segment_size
        global mxen
        global encrdecr
        global flag_for_mul_inp
        global flag_side
        global flag_json_dont_overwrite

        # Saving Base Request from client and server. It is needed for forming proper json formation before encryption.
        if flag_json_dont_overwrite==0:
            file=open("reqjson.txt","w") if flag_side==0 else open("resjson.txt","w")
            file.write(re_body_text)
            file.close()
            flag_json_dont_overwrite=1

        #Forming Decryption Function name which will be called from the appropriate module
        decryption_final='enc_dec_'+cipMethod.lower()+"."+cipMethod.lower()+"_"+cmode.lower()+"_dec"
        
        r"""
        Fixing block size . Useful while extracting IV.
        Block Size= 16/24/32 bytes in AES.
        Block Size= 8 bytes in DES/DES3. 
        We have by default taken blocksize = 16 if cipher method is AES, you can change it here. 
        """
        block=16 if "aes" in decryption_final else 8
        
        dkey=keyf # Saving decryption key.
        mode=padding # Saving padding mode.

        # Forming the final padding function which will be called from the EncDec module.
        dencod="EncDec."+mode_enco+"Dec"
 
        iv_info=ivs # Saving IVS, 1/2 or None if IV is not sent with Cipher Text
        if iv_info is not None:
            iv_info='beg' if iv_info=='1' else 'end' #beg is IV is appened at beginning, end if at end.

        # Saving segment size. Will be None is mode is not CFB.
        seg_size=segment_size

        # This is the actual decryption function. 
        def decryption(todecrypt):
            orignal=todecrypt # This is the cipher text which is to be decrypted.

            try:
                decoded_value=eval(dencod)(todecrypt) # Decoding the cipher text and storing in decoded_value.

                if iv_info is not None: 
                    if iv_info=='beg' or iv_info=='end': # Mode is not ECB.
                        
                        # Extracting IV from Cipher Text.
                        # Usually IV is equal to block size. Hence extracting block sized bytes from appropirate position
                        iv=decoded_value[0:block] if iv_info=='beg' else decoded_value[-block:]
                        
                        # Extracting actual data which will be decrypted.
                        ct=decoded_value[16:] if iv_info =='beg' else decoded_value[0:len(decoded_value)-block]
                        
                        # Decrypting and storing the decrypted text in todecrypt
                        todecrypt=eval(decryption_final)(dkey,ct,iv,mode) if seg_size == None else eval(decryption_final)(dkey,ct,iv,mode,seg_size)
                        
                        # Encoding IV and storing in text file as it will be needed at the encryption.
                        iv=eval(mode_encod)(iv)
                        file=open("iv.txt","w") if encrdecr=='d' else open("iv.txt","a")
                        file.write(str(iv)+"\n")
                        file.close()

                    elif iv_info is None and ivf is not None: 
                    # IV is not appended with Cipher Text. It is inputted by user.
                        iv=ivf # Saving inputted IV.
                        ct=decoded_value # Since no IV appended with Cipher Text, entire Cipher Text will be decrypted.
                        todecrypt=eval(decryption_final)(dkey,ct,iv,mode) if seg_size == None else eval(decryption_final)(dkey,ct,iv,mode,seg_size)   
                else:
                    #If this is called, then no IV was required. Meaning most probably ECB Mode.
                    todecrypt=eval(decryption_final)(dkey,decoded_value,mode)

                return todecrypt
            
            except Exception:
                #If decryption fails, return original text.
                return original

        r"""
        The next block of functions handle decryption of different content types. 
        Depending upon the content type, the parameters and body are passed to these functions. 
        These functions call the main decryption function and after decrypting the text make the required changes to the body.
        Then the body (with encrypted text replaced by decrypted text) is returned.
        -------------------------------------------------------------------------------------
        """

        def decrypt_json(parameters,re_body_text):
            original=re_body_text
            body=json.loads(re_body_text) # Since json object is passed as string, we are converting it back to json object here.     
            try:
                for i in parameters: # We iterate over the list of keys whose values have to decrypted.
                    body[i]=decryption(body[i]) # Decrypting the values.
                return json.dumps(body).replace("\\","") # Converting json object back to string.
            except Exception:
                # Exceptions can arise due to json_loads and json_dumps. In such a case, return original. 
                return original

        def decrypt_xml(parameters,re_body_text):
            original=re_body_text
            try:
                e = ET.fromstring(str(re_body_text)) # Parse the string and convert to XML object.
                for elt in e.iter(): # Iterate over the tags.
                    if elt.tag in parameters and elt.text is not None: # Check if tag name is present in parameters and tag's text is not Empty.
                            elt.text=decryption(elt.text)
                re_body_text=ET.tostring(e, encoding='utf8', method='xml') # Converting the XML object back to XML string.
                return re_body_text
            except Exception:
                return original

        def decrypt_www_form_urlencoded(parameters,re_body_text):
            original=re_body_text
            try:
                # Splitting the body in a dictionary.Key, value pairs are extracted by splitting about =.
                elem_dic=dict(x.split('=') for x in res_body_text.split("&")) 
                for i in elem_dic:
                    if elem_dic[i] in parameters: #  If key is in parameters list, then decrypt.
                        elem_dic[i]=decryption(elem_dic[i])
                # The required replacements have been made in the dictionary. Now we form the string back from the modified dictionary. 
                new_text=""
                for key, value in elem_dic.iteritems():
                    new_text=new_text+key+"="+value+"&" # Key, Value pairs are separated by &.
                new_text_final=new_text[:-1] #Removing last &
                return new_text_final
            except Exception:
                return original

        def decrypt_multipart_form(parameters,re_body_text):
            file=open("temp.txt","r") # We open a temporary text file where entire body is stored.
            a=file.readlines() # Reading the body and splitting by new line character.
            boundary=re_body_text # Boundary Value is returned by get_body_text function.
            lis="" # We are forming a new string. 
            i=0
            while i<len(a)-1:
                if boundary in a[i]: 
                    # We start at boundary line. After that, there are one or two line starting with "content".
                    # Then a blank line is left, after which main content is there till the next boundary line.
                    lis=lis+a[i]
                    while a[i] != '\n': # New line character encountered after boundary line. 
                        lis=lis+a[i]
                        i=i+1
                    lis=lis+a[i]
                    i=i+1 # Actual content is on the next line.
                    temp="" # This string will store all text from the new line character to the next boundary line.
                    while boundary not in a[i]:
                        temp=temp+a[i]
                        i=i+1
                    if temp in parameters: # If parameter is matched, it will decrypt.
                        temp=temp[:-1]
                        temp=decryption(temp)
                        temp=temp+'\n'
                    lis=lis+temp
                file.close()
            return lis # This new string has the entire modified body.

            r"""--------------------------------------------------------------------------------------"""

        
        def fetch_parameters(list_parameters,flag_side):
            
            r"""
            This function will store all parameters which have to be decrypted in text files. 
            List of parameters to be stored is sent to this function.
            reqpara.txt will contain request side parameters.
            respara.txt will contain the response side parameters.
            This function returns the parameters in a list.
            """
            
            file=open("reqpara.txt","w") if flag_side==0 else open("respara.txt","w")
            for i in list_parameters:
                file.write(str(i+"\n"))
            file.close()
            file=open("reqpara.txt","r") if flag_side==0 else open("respara.txt","r")
            parameters=file.readlines()
            for i in range(0,len(parameters)):
                parameters[i]=parameters[i].replace("\n","")
            file.close()
            return parameters

        if mxen == '1':
            res_body_text=decryption(re_body_text) # Decrypting Entire Body
            return re_body_text

        if mxen =='2': # Decrypting all values. 

            if con_type==2 or con_type==0:
                sys.exit('This object has no key value pair!')

            list_parameters=[]

            if con_type==1:
                original=re_body_text
                try:
                    body=json.loads(re_body_text)
                    # Extracting all key names and storing in a list.
                    for key in body:
                        list_parameters.append(key) 
                    parameters=fetch_parameters(list_parameters,flag_side) # Storing Parameters and getting the list.
                    return decrypt_json(parameters,re_body_text)
                except Exception:
                    return original
          
            if con_type==3:
                original=re_body_text
                try:
                    e = ET.fromstring(str(re_body_text))
                    # Extracting all valid keys (whose text is not empty) and storing in list.
                    for elt in e.iter():
                        if elt.text is not None:
                            list_parameters.append(elt.tag)
                    parameters=fetch_parameters(list_parameters,flag_side) # Storing Parameters and getting the list.
                    return decrypt_xml(parameters,re_body_text)
                except Exception:
                    return orignal

            if con_type==4:
                original=re_body_text
                try:
                    elem_dic=dict(x.split('=') for x in res_body_text.split("&"))
                    # Extracting all keys and storing in list.
                    for i in elem_dic:
                        list_parameters.append(i)
                    parameters=fetch_parameters(list_parameters,flag_side) # Storing Parameters and getting the list.
                    return decrypt_www_form_urlencoded(parameters,re_body_text)
                except Exception:
                    return original

            if con_type==5:
                original=re_body
                file=open("temp.txt","w")
                file.write(original) # Saving body in a file.
                file.close()
                file=open("temp.txt","r") 
                a=file.readlines()
                lis=list()
                boundary=re_body_text
                i=0
                # Same logic for getting the text as explained in decrypt_multipart_form()
                while i<len(a)-1:
                    if boundary in a[i]:
                        while a[i] != '\n':
                            i=i+1
                        i=i+1
                        temp=""
                        while boundary not in a[i]:
                            temp=temp+a[i]
                            i=i+1
                        temp=temp[:-1]
                        lis.append(temp)
                parameters=fetch_parameters(lis,flag_side) # Storing Parameters and getting the list.
                return decrypt_multipart_form(parameters,re_body)

            if con_type==0 or con_type==2:
                print("We have not yet identified how to identify encrypted parameters in these content types")
                return re_body

        if mxen =='3': # Decrypting multiple values.
            
            if flag_for_mul_inp==0: # Info about values to be decrypted will be asked only once.
                print colored("Enter keys (if json/xml/x-www-form-urlencoded). If others, enter values.Separate by a single space.","green")
                lis_of_parameters=raw_input() 
                list_parameters=lis_of_parameters.split()
                parameters=fetch_parameters(list_parameters,flag_side) # Storing the parameters in file and getting the list.
                flag_for_mul_inp=1
            else: # If parameters have already been stored, open the file and read the parameters.
                if flag_side==0:
                    file=open("reqpara.txt","r")
                elif flag_side==1:
                    file=open("respara.txt","r")
                parameters=file.readlines()
                for i in range(0,len(parameters)):
                    parameters[i]=parameters[i].replace("\n","")
                file.close()

            if con_type==1:
                return decrypt_json(parameters,re_body_text)

            if con_type==3:
                return decrypt_xml(parameters,re_body_text)

            if con_type==4:
                return decrypt_www_form_urlencoded(parameters,re_body_text)

            if con_type==5:
                file=open("temp.txt","w")
                file.write(re_body)
                file.close()
                return decrypt_multipart_form(parameters,re_body_text)

            if con_type==0 or con_type==2:
                print("We have not yet identified how to identify encrypted parameters in this content types")
                return re_body
        else:
            sys.exit("Please enter valid mxen")

# Decryption Block ends here------------------------------------------------------------------------------------------------------------------


    def save_handler(self, req, req_body, res, res_body,req_body_original,res_body_original):
        self.print_info(req, req_body, res, res_body,req_body_original,res_body_original)



def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    port = sys.argv[1]
    port=int(port)
    server_address = ('192.168.0.217', port)
    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)
    sa = httpd.socket.getsockname()
    print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()


if __name__ == '__main__':

    r"""
    Command Line Arguments-
    1) Port
    2) Cipher Method - AES/DES/DES3 etc.
    3) Key
    4) Cipher Mode - CBC/ECB/CFB etc
    5) Encoding Mode - Base64/Hex/Oct etc
    6) Choice:
            1)Encrypt/Decrypt Enitre body
            2)Encrypt/Decrypt all values in json/xml
            3)Encrypt/Decrypt multiple parameters\n")
    7) 'e' if this script is P2, 'd' is this is P1
    8) Padding Mode - CMS/Bit/ISO etc
    9) Position of IV : 1 for Starting, 2 for Ending
    10) Log Level - 0/1/2
    11) Segment Size= Only in CFB mode, must be multiple of 8. If left blank, 8 will be taken by default
    """
    
    global cipMethod
    global keyf
    global cmode
    global ivf
    global ivs
    global segment_size
    global padding
    global mode_enco
    global mode_encod
    global mxen
    global encrdecr
    global iv1
    global flag_for_mul_inp
    global flag_for_url
    global target
    global flag_side
    global flag_json_dont_overwrite
    flag_json_dont_overwrite=0
    flag_side=0
    flag_for_url=0
    flag_for_mul_inp=0
    fname = Path("requirements.dat")
    if (fname.exists()):
        fileReq = open("requirements.dat",'r')
        dic = json.loads(fileReq.read())
        cipMethod = dic['cipMethod']
        keyf = dic['keyf']
        cmode = dic['cmode']
        ivf = dic['ivf']
        ivs = str(dic['ivs']) if cmode !='ECB' else None
        segment_size = str(dic['segment_size']) if dic['segment_size']!= None else None
        padding = dic['padding']
        mode_enco = dic['mode_enco']
        mode_encod = "EncDec." + mode_enco + "Enc"
        mxen = str(dic['mxen'])
        encrdecr = str(dic['encrdecr'])
        logslevel = int (dic['logslevel'])
        if encrdecr == 'e':
            encrdecr ='d'
        else:
            encrdecr = 'e'
        fileReq.close()
    else:
        dic = {}
        cipMethod = sys.argv[2]
        dic['cipMethod'] =  cipMethod
        keyf = sys.argv[3]
        dic['keyf'] = keyf
        cmode = sys.argv [4]
        dic['cmode'] = cmode
        choose = raw_input ("Want to enter IV(y/n)") # If IV is not entered, it is assumed that IV is not hard-cored and is sent with each ciphertext. Hence, IV is extracted from the ciphertext.
        ivf = raw_input("Enter IV") if cmode != 'ECB' and choose == 'y' else None
        dic['ivf'] = ivf
        ivs = str(sys.argv[9]) if cmode!='ECB' else None #raw_input("Positin of IV, the position at which IV is appended with cipher text: At Starting(1),Ending(2) or Not appended(3)")
        dic['ivs'] = ivs
        segment_size = str(sys.argv[11]) if cmode == 'CFB' else None
        dic['segment_size'] = segment_size
        padding = sys.argv[8]  #raw_input("Padding format: Bit, CMS, ZeroLen, Null, ISO, Random,None: ")
        dic['padding'] = padding
        mode_enco = sys.argv[5] #raw_input("Mode of Encoding: Base64/AsciiHex/Bin/Oct/Hex/URL: ")
        dic['mode_enco'] = mode_enco
        mode_encod = "EncDec." + mode_enco + "Enc"
        mxen= str(sys.argv[6]) #raw_input("1)Encrypt/Decrypt Enitre body\n2)Encrypt/Decrypt all values.\n3)Encrypt/Decrypt multiple parameters\n")
        dic['mxen'] = mxen
        encrdecr = str(sys.argv[7])  # e for encryption, d for decryption
        dic['encrdecr'] = encrdecr
        logslevel = int (sys.argv[10])
        dic['logslevel'] = logslevel
        fileReq = open("requirements.dat",'w+')
        fileReq.write(json.dumps(dic))
        fileReq.close()
    test()
