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
import EncDec 
import enc_dec_aes 
import enc_dec_des 
import enc_dec_des3 
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
                self.response_handler(req, req_body, res, '')
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

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
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

    #Function to filter headers. 
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

    #Function to encode body content if specified in the header
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

    #Function to decode body content if specified in the header
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

    #Function to print request and responses
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
                    print "poppppppp"
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

    #Input details required for Encryption of requests
    def inputDetails(self):
        cipMethod = raw_input("Encryption Method- AES/DES/DES3: ") 
        key = raw_input("Key: ")
        mode =raw_input("mode: ECB/CBC/CFB: ")
        #ivs,iv = self.extractIV() if mode not in 'ECB' else None
        ivNum = raw_input("IV is entered once for all keywords(1) or to be extracted with every block(2): ")
        segment_size = self.getSegmentSize() if mode == 'CFB' else None
        padding = raw_input("Padding format: Bit, CMS, ZeroLen, Null, ISO, Random,None: ")
        mode_enco =raw_input("Mode of Encoding: Base64/AsciiHex/Bin/Oct/Hex/URL: ")
        mode_enco = "EncDec." + mode_enco + "Enc"
        mxen=raw_input("Mode of Encryption: Full request body(1) or parameters(2): ")
        return cipMethod,key,mode, ivNum, segment_size, str(padding), mode_enco, mxen

    #Function to extract IV
    def extractIV(self, req_body,mode_enco):
        ivs = raw_input("IV: Starting(1) or Ending(2): ")
        #For obtaining IV from Suraksha-
        #'.' is to be added to the request body to separate IV encoded block and decrypted message
        identifier = '.'
        iv = req_body.split(identifier)[0]
        iv = EncDec.Base64Dec(iv)
        print iv
        print type(iv)
        return ivs,iv

    #Function to extract text to encrypt
    def getBodyEnc(self, requestString):
        #For Suraksha app-
        identifier = '.'
        return requestString.split(identifier)[1]

    #Function to obtain segment size for Encryption
    def getSegmentSize():
        seg_size = raw_input("Segment Size(0 if does not exist): ")
        return seg_size

    def request_handler(self, req, req_body):
        print req_body
        #Input of parameters. ivNum contains the number of IVs in the request. If different parameters
        #contain different IV, then obtained while encryption
        cipMethod,key,mode, ivNum, segment_size, padding, mode_enco, mxen = self.inputDetails()
        print type(padding)
        ivs,iv = self.extractIV(req_body,mode_enco) if ivNum == '1' else None,None


        #Encryption of full request body:
        if (int(mxen)==1):
            if (ivs == '1'):
                req_body=self.encr(cipMethod, req_body, key, padding, iv,mode, segment_size)
                req_body = iv + req_body
            elif (ivs == '2'):
                req_body=self.encr(cipMethod, req_body, key, padding, iv,mode, segment_size)
                req_body = req_body + iv
            req_body = eval(mode_enco)(req_body)
            return req_body

        #Encryption of Parameters: Encrypts Values only: 
        if (int(mxen)==2):
            content_type = req.headers.get('Content-Type', '')
            #Handler if Content-Type is application/json:
            if content_type.startswith('application/json'):
                req_body_text = None
                try:
                    #Loads the request body in a dictionary json_obj. Traverses keys and values.
                    #Encrypts the given value if user inputs Y
                    json_obj = json.loads(req_body)
                    for ele in json_obj.keys():
                        print "Encrypt " + ele + "(Y/N)"
                        choice =raw_input()
                        if (choice=='Y' or choice=='y'):
                            #Calls getBodyEnc to get request body to encrypt (If IV is present in the request, temp
                            # temp will contain the text to be encrypted. After Encryption, IV is concatenated 
                            # according to the position specified in'ivs'.)
                            if (ivNum != '1'):
                                ivs,iv = self.extractIV(json_obj[ele],mode_enco)
                            temp = self.getBodyEnc(json_obj[ele])
                            print temp
                            temp= self.encr(cipMethod, temp, key, padding, iv, mode, segment_size)
                            if (ivs == '1'):
                                temp = iv + temp
                            elif (ivs == '2'):
                                temp = temp + iv
                            json_obj[ele] = eval(mode_enco)(temp)
                            print json_obj[ele]
                        elif (not choice=='N' or not choice == 'n'):
                            print "Invalid Choice"
                    json_str = json.dumps(json_obj, indent=2)
                    #print json_str
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except Exception:
                    #print "hi exception"
                    req_body_text = req_body
                    print (traceback.format_exc())
                return req_body_text
            else:
                #Handler if the content-type is not application/json. File 'reqHandler' is opened and request 
                #is written. The user is required to encrypt the plaintext required and paste back in the file.
                #'e': encryption. 'q': stop encryption loop
                reqFile = open('reqHandler.dat', 'w+')
                reqFile.write(str(req_body))
                reqFile.close()
                choice =raw_input("Enter e for encryption of text and q to exit")
                while (choice!='q'):
                    encText = raw_input("Enter text to encrypt")
                    if (ivNum != '1'):
                        ivs,iv = self.extractIV(encText,mode_enco)
                    encText = self.getBodyEnc(encText)
                    encText = self.encr(cipMethod,encText, key, padding, iv, mode, segment_size)
                    if (ivs == '1'):
                        encText = iv + encText
                    else:
                        encText = encText + iv
                    encText = eval(mode_enco)(encText)
                    print encText
                    choice = raw_input("Do you want to continue? e(encrypt)/q (quit)")
                reqFile = open('reqHandler.dat', 'r')
                req_body_text = reqFile.read()
                reqFile.close()
                print req_body_text
                return req_body_text

    # #Encoding functions. User has to pass encoding method and msg to be encoded. 
    # def enco(self,encoMethod, msg):
    #     if (encoMethod == 'B64'):
    #         return EncDec.Base64Enc(msg)
    #     elif (encoMethod == 'Ahex'):
    #         return EncDec.AsciiHexEnc(msg)
    #     elif (encoMethod == 'Bin'):
    #         return EncDec.BinEnc(msg)
    #     elif (encoMethod == 'Oct'):
    #         return EncDec.OctEnc(msg)
    #     elif (encoMethod == 'Hex'):
    #         return EncDec.HexEnc(msg)
    #     elif (encoMethod == 'URL'):
    #         return EncDec.URLEnc(msg)
    
    #Encryption Functions. User has to pass the required parameteres only.
    def encr(self, cipMethod, msg, key, padding, iv,mode,segment_size):
        if (cipMethod=='AES'):
            if (mode == 'ECB'):
                return enc_dec_aes.aes_ecb_enc(key,msg,padding)
            elif (mode == 'CBC'):
                return enc_dec_aes.aes_cbc_enc(key,msg,iv,padding)
            elif (mode == 'CFB'):
                return enc_dec_aes.aes_cfb_enc(key,msg,iv,padding,int(segment_size))

        if (cipMethod == 'DES'):
            if (mode == 'ECB'):
                return enc_dec_des.des_ecb_enc(key, msg, padding)
            elif (mode == 'CBC'):
                return enc_dec_des.des_cbc_enc(key, msg, iv, padding)
            elif (mode == 'CFB'):
                return enc_dec_des.des_cfb_enc(key, msg, iv, padding, int(segment_size))

        if (cipMethod == 'DES3'):
            if (mode == 'ECB'):
                return enc_dec_des3.des3_ecb_enc(key, msg, padding)
            elif (mode == 'CBC'):
                return enc_dec_des3.des3_cbc_enc(key, msg, iv, padding)
            elif (mode == 'CFB'):
               return enc_dec_des3.des3_cfb_enc(key, msg, iv, padding, int(segment_size))      

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        self.print_info(req, req_body, res, res_body)


def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    #Specify port. Default port: 8080. Uses IPv6 loopback address.
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 8080
    server_address = ('::1', port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()

if __name__ == '__main__':
    test()