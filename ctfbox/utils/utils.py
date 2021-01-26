import re
from os import path
from base64 import (b32encode, b64decode, b64encode, urlsafe_b64decode,
                    urlsafe_b64encode)
from binascii import hexlify, unhexlify
from hashlib import md5 as _md5
from hashlib import sha1 as _sha1
from hashlib import sha256 as _sha256
from hashlib import sha512 as _sha512
from json import dumps, loads
from random import choice, randint
from string import ascii_lowercase, digits
from struct import pack, unpack
from typing import Dict, Union
from urllib.parse import urlparse, quote_plus, unquote_plus
from functools import wraps
from http.server import BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor

import jwt

DEFAULT_ALPHABET = list(ascii_lowercase + digits)


class _Context:
    def __init__(self, value=None):
        self.value = value


class _Multier():

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


def Threader(number: int, timeout: int = None, retry: int = 2):
    """
    A simple decorator function that can decorate the function to make it multi-threaded.
    """
    def decorator(func):
        if isinstance(number, int):
            pool = ThreadPoolExecutor(number)
        else:
            raise TypeError(
                "Invalid type: %s for number"
                % type(number)
            )

        @wraps(func)
        def wrapped(*args, **kwargs):
            return _Multier(
                pool.submit(func, *args, **kwargs),
                timeout,
                retry,
                pool,
            )
        return wrapped
    return decorator


class _ProvideHandler(BaseHTTPRequestHandler):

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
            print("[-] " + str(e))


def url_encode(s: str, encoding: str = 'utf-8') -> str:
    try:
        return quote_plus(s, encoding=encoding)
    except Exception:
        return ""


def url_decode(s: str, encoding: str = 'utf-8') -> str:
    try:
        return unquote_plus(s, encoding=encoding)
    except Exception:
        return ""


def base64_decode(s: str, encoding='utf-8') -> str:
    try:
        return b64decode(s.encode()).decode(encoding=encoding)
    except Exception:
        return ""


def base64_encode(s: str, encoding='utf-8') -> str:
    try:
        return b64encode(s.encode()).decode(encoding=encoding)
    except Exception:
        return ""


def bin2hex(s: str) -> str:
    try:
        return hexlify(s.encode()).decode()
    except Exception:
        return ""


def hex2bin(s: str) -> str:
    try:
        return unhexlify(s).decode()
    except Exception:
        return ""


def sha1(s: str, encoding='utf-8') -> str:
    try:
        return _sha1(s.encode(encoding=encoding)).hexdigest()
    except Exception:
        return ""


def sha256(s: str, encoding='utf-8') -> str:
    try:
        return _sha256(s.encode(encoding=encoding)).hexdigest()
    except Exception:
        return ""


def sha512(s: str, encoding='utf-8') -> str:
    try:
        return _sha512(s.encode(encoding=encoding)).hexdigest()
    except Exception:
        return ""


def md5(s: str, encoding='utf-8') -> str:
    try:
        return _md5(s.encode(encoding=encoding)).hexdigest()
    except Exception:
        return ""


def random_int(minN: int = 0, maxN: int = 1024) -> int:
    try:
        return randint(minN, maxN)
    except Exception:
        return 0


def random_string(n: int = 32, alphabet: str = DEFAULT_ALPHABET) -> str:
    try:
        return ''.join([choice(alphabet) for _ in range(n)])
    except Exception:
        return ""


def json_encode(obj) -> object:
    try:
        return dumps(obj)
    except Exception:
        return object()


def json_decode(data) -> str:
    try:
        return loads(data)
    except Exception:
        return ""


def jwt_encode(header: dict, payload: dict, key=None, algorithm=None) -> str:
    if key is None and algorithm is None:
        # dict to json
        hearder_json = dumps(header, sort_keys=True, separators=(',', ':'))
        payload_json = dumps(payload, sort_keys=True, separators=(',', ':'))
        # json to base64
        header_b64 = urlsafe_b64encode(
            hearder_json.encode()).replace(b'=', b'')
        payload_b64 = urlsafe_b64encode(
            payload_json.encode()).replace(b'=', b'')

        return (header_b64 + b'.' + payload_b64).decode()
    else:
        return jwt.encode(payload=payload, key=key, algorithm=algorithm, headers=header)


def jwt_decode(token: str) -> bytes:
    data = [b''] * 3
    try:
        for i, each in enumerate(token.split('.')):
            padding = 4 - len(each) % 4
            if padding:
                each += ('=' * padding)
            data[i] = urlsafe_b64decode(each.encode())
    except Exception:
        pass

    return b'-'.join(data)


def od_parse(data: str) -> Dict[str, Union[str, list]]:
    """Parse od command output without argument, return a dict with the following keys: hex, ascii, list, text
    Returns:
        dict: with key hex, ascii, list, text
    """
    text, asc_data, hex_data, list_data = "", "", "", []
    for line in data.split("\n"):
        for d in line.split(" ")[1:]:
            h = hex(int(d, 8))[2:].zfill(4)
            a, b = int(h[2:], 16), int(h[:2], 16)
            text += chr(a) + chr(b)
            hex_data += "0x%x 0x%x " % (a, b)
            asc_data += "%s %s " % (a, b)
            list_data += [a, b]
    return {"hex": hex_data.strip(), "ascii": asc_data.strip(), "list": list_data, "text": text}
