from http.server import BaseHTTPRequestHandler
from hashlib import md5, sha1, sha256, sha512
from os import path
from traceback import print_exception
from urllib.parse import urlparse
from enum import Enum

filepath = str
content = bytes
routePath = str
contentType = str


class HashType(Enum):
    MD5 = 0
    SHA1 = 1
    SHA256 = 2
    SHA512 = 3


HASHTYPE_DICT = {HashType.MD5: md5, HashType.SHA1: sha1, HashType.SHA256: sha256, HashType.SHA512: sha512}


class ArugmentError(Exception):
    pass


class Context:
    def __init__(self, value=None):
        self.value = value


class Multier():

    def __init__(self, future, timeout, retry, pool):
        self._future = future
        self._timeout = timeout
        self._retry = retry
        self._pool = pool

    def __getattr__(self, name):
        if (name == 'result'):
            return self.join()
        elif (name == 'pool'):
            return self._pool
        elif (name == 'exception'):
            return self._future.exception()
        elif (name == 'running'):
            return self._future.running()
        elif (name == 'done'):
            return self._future.done()
        else:
            return self._future.__getattribute__(name)

    def join(self):
        try:
            return self._future.result(self._timeout)
        except Exception:
            if (self._retry > 0):
                self._retry -= 1
                return self.join()
            else:
                self._future.result = lambda: None


class ProvideHandler(BaseHTTPRequestHandler):

    def __init__(self, ServeFiles, *args, **kwargs):
        self.serveFiles = ServeFiles
        super().__init__(*args, **kwargs)

    def guess_type(self, filename):
        mimetype = 'text/plain'
        if filename.endswith(".html"):
            mimetype = 'text/html'
        if filename.endswith(".jpg"):
            mimetype = 'image/jpg'
        if filename.endswith(".gif"):
            mimetype = 'image/gif'
        if filename.endswith(".js"):
            mimetype = 'application/javascript'
        if filename.endswith(".css"):
            mimetype = 'text/css'
        return mimetype

    def do_GET(self):
        sendReply = False
        querypath = urlparse(self.path)
        filepath = querypath.path
        try:
            for fileInfo in self.serveFiles:
                lenOfFileInfo = len(fileInfo)
                arg = fileInfo[0]
                filename = ""
                content = b''
                if isinstance(arg, bytes):
                    content = arg
                elif isinstance(arg, str) and path.isfile(arg):
                    try:
                        fp = open(arg, 'rb')
                        content = fp.read()
                        filename = path.basename(arg)
                        fp.close()
                    except Exception:
                        continue
                else:
                    continue
                # ? No routing and no file name
                if filename == "" and lenOfFileInfo < 2:
                    continue
                route = "/"+filename if lenOfFileInfo < 2 else fileInfo[1]
                content_type = self.guess_type(
                    route) if lenOfFileInfo < 3 else fileInfo[2]
                if filepath == route:
                    sendReply = True
                    self.send_response(200)
                    self.send_header("Content-type", content_type)
                    self.end_headers()
                    self.wfile.write(content)
            if not sendReply:
                self.send_response(404)
                self.wfile.write(b"404 Not Found\n")
            return
        except Exception as e:
            print_exception(e)
            print("[-] " + str(e))

