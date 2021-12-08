import base64
import binhex
import binascii
from bz2 import decompress as bz2decompress
from concurrent.futures import ThreadPoolExecutor
import codecs 
from functools import wraps
from hashlib import md5 as _md5
from hashlib import sha1 as _sha1
from hashlib import sha256 as _sha256
from hashlib import sha512 as _sha512
from http.server import BaseHTTPRequestHandler
from json import dumps, loads
from os import path
import html
import collections
from random import choice, randint
from re import sub
from string import ascii_lowercase, digits
from traceback import format_exc, print_exc
from typing import Dict, Union
import uu
import urllib.parse 
import io


import jwt

DEFAULT_ALPHABET = list(ascii_lowercase + digits)


class Context:
    def __init__(self, value=None):
        self.value = value


class _Multier():

    def __init__(self, future, timeout,):
        self._future = future
        self._timeout = timeout
        self._traceback = None

    def __getattr__(self, name):
        if (name == 'result'):
            return self.join()
        elif (name == 'exception'):
            return self.join(True)
        elif (name == 'traceback'):
            self.join(True)
            return self._traceback
        elif (name == 'running'):
            return self._future.running()
        elif (name == 'done'):
            return self._future.done()
        else:
            return self._future.__getattribute__(name)

    def join(self, exceptionFlag: bool = False):
        try:
            result = self._future.result()
            return result
        except Exception as e:
            if exceptionFlag:
                self._traceback = format_exc()
                return e
            return None


def retryWrapper(retry_time: int = 2):
    def decorator(func):
        def inner(*args, **kwargs):
            max_retry = retry_time
            while max_retry >= 0:
                try:
                    ret = func(*args, **kwargs)
                    return ret
                except Exception as e:
                    max_retry -= 1
                    if max_retry < 0:
                        raise e
        return inner
    return decorator


def Threader(number: int, timeout: int = None, retry: int = 2):
    """A simple decorator function that can decorate the function to make it multi-threaded.

    Args:
        number (int): thread number
        timeout (int, optional): function run timeout. Defaults to None.
        retry (int, optional): number of retries. Defaults to 2.

    Example:
        from ctfbox import Threader, random_string, random_int
    from time import sleep

    @Threader(10)
    def exp(i: int):
        sleep(random_int(1, 5))
        return "%d : %s" % (i, random_string())

        tasks = [exp(i) for i in range(100)] # 100 tasks
        for task in tasks:
            # task.result return when a task completed
            # task is a concurrent.futures.Future with some attributes
            # result, running ,done, exception, traceback
            print('result: %s running: %s done: %s exception: %s' % (task.result, task.running, task.done, task.exception))
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
            retry_func = retryWrapper(retry)(func)
            return _Multier(
                pool.submit(retry_func, *args, **kwargs),
                timeout,
            )
        return wrapped
    return decorator


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
        except Exception:
            print_exc()


class BlindXXEHandler(BaseHTTPRequestHandler):

    def __init__(self, content, bz2content, customcontent, *args, **kwargs):
        self.content = content
        self.bz2content = bz2content
        self.customcontent = customcontent
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        sendReply = False
        querypath = urlparse(self.path)
        query_dict = {}
        for kv in querypath.query.split("&"):
            v = kv.split("=")
            if len(v) > 1:
                query_dict[v[0]] = unquote_plus(v[1])
            else:
                query_dict[v[0]] = None
        filepath = querypath.path
        try:
            if filepath == "/evil.dtd":
                sendReply = True
                self.send_response(200)
                self.send_header("Content-type", "application/xml-dtd")
                self.end_headers()
                if "bz2" in query_dict:
                    content = self.bz2content
                else:
                    content = self.content
                readFile = query_dict.get("file", "/etc/passwd")
                content = content.replace(b"!readFile!", readFile.encode())
                self.wfile.write(content)
            elif filepath == "/custom.dtd":
                sendReply = True
                self.send_response(200)
                self.send_header("Content-type", "application/xml-dtd")
                self.end_headers()
                content = self.customcontent
                link = query_dict.get("link", "")
                content = content.replace(b"!link!", link.encode())
                self.wfile.write(content)
            else:
                data = querypath.query
                try:
                    data = b64decode(data)
                    data = bz2decompress(data)
                except Exception:
                    pass
                print("Receive file content:\n" + data.decode())
                sendReply = True
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'<?xml version="1.0"?>\n<root></root>\n')
            if not sendReply:
                self.send_response(404)
                self.wfile.write(b"404 Not Found\n")
            return
        except Exception:
            print_exc()


def url_encode(s: str, encoding: str = 'utf-8') -> str:
    try:
        return quote_plus(s, encoding=encoding)
    except Exception:
        return ""


def force_url_encode(data: str) -> str:
    """force url encode normal string

    Args:
        data (str): normal string

    Returns:
        str: url encoded stirng
    """
    string = bin2hex(data)
    if not string:
        return ""

    return "".join("%" + string[i:i+2] for i in range(0, len(string), 2))


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


def base32_decode(s: str, encoding='utf-8') -> str:
    try:
        return b32decode(s.encode()).decode(encoding=encoding)
    except Exception:
        return ""


def base32_encode(s: str, encoding='utf-8') -> str:
    try:
        return b32encode(s.encode()).decode(encoding=encoding)
    except Exception:
        return ""


def base16_decode(s: str, encoding='utf-8') -> str:
    try:
        return b16decode(s.encode()).decode(encoding=encoding)
    except Exception:
        return ""


def base16_encode(s: str, encoding='utf-8') -> str:
    try:
        return b16encode(s.encode()).decode(encoding=encoding)
    except Exception:
        return ""


def html_decode(s: str) -> str:
    def replace(matched):
        value = int(matched.group(1))
        return chr(value)

    def replace_hex(matched):
        value = int(matched.group(1), 16)
        return chr(value)
    s = sub(r'&#x(\w+);', replace_hex, s)
    s = sub(r'&#(\w+);', replace, s)
    return s


def html_encode(s: str, asHex: bool = False) -> str:
    if asHex:
        ss = "".join(f"&#x{hex(ord(c))[2:]};" for c in s)
    else:
        ss = "".join(f"&#{ord(c)};" for c in s)
    return ss


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


def rot_encode(data: str, n: int) -> str:
    """rotate by custom places

    Args:
        data (str): data to be encoded
        n (int): custom places

    Returns:
        str: Encoded data

    Example:
        rot_encode("aaa", 25) -> "zzz"
    """
    n = (26 - (-n % 26)) * 2
    chars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz"
    trans = chars[n:]+chars[:n]
    def rot_char(c): return trans[chars.find(c)] if chars.find(c) > -1 else c
    return ''.join(rot_char(c) for c in data)

def auto_decode(s: str) -> Dict[str,str]:
    """Decrypted in the usual way

    Args:
        s(str): data to be decoded

    Returns:
        Dict[str,str]: Results of decryption

    Example:
        auto_decode("MTEx") -> 
        {"'Base64': '111',
        'Base85': "b'E\\x84\\xc7'",
        'ROT13 ': 'ZGRk',
        'Error': 'Base32, Base16, Ascii85, Uuencoding',
        'No change': 'HTML'"}
    """
    return _atdecode(s.encode())

def _wrap_uu(func):
    def new_func(in_bytes):
        in_file = io.BytesIO(in_bytes)
        out_file = io.BytesIO()
        func(in_file, out_file)
        out_file.seek(0)
        return out_file.read()
    return new_func

def _wrap_rot13(func):
    def new_func(in_bytes):
        in_str = in_bytes.decode()
        out_str = func(in_str, 'rot-13')
        return out_str.encode()
    return new_func

def _wrap_html(func):
    def new_func(in_bytes):
        in_str = in_bytes.decode()
        out_str = func(in_str)
        return out_str.encode()
    return new_func

_funcs = collections.OrderedDict()
_funcs['Base64'] = base64.standard_b64decode
_funcs['Base32'] = base64.b32decode
_funcs['Base16'] = base64.b16decode
_funcs['Ascii85'] = base64.a85decode
_funcs['Base85'] = base64.b85decode
_funcs['Uuencoding'] = _wrap_uu(uu.decode)
_funcs['ROT13'] = _wrap_rot13(codecs.decode)
_funcs['HTML'] = _wrap_html(html.unescape)
def _decode_bytes(unknown_bytes, func, encoding):
    decoded_bytes = None
    try:
        decoded_bytes = func(unknown_bytes)
    except binascii.Error:
        pass
    except binhex.Error:
        pass
    except uu.Error:
        pass
    except ValueError:
        pass
    return decoded_bytes

def _atdecode(unknown_bytes):
    failed_encodings = []  
    no_difference = []
    output_dict = collections.OrderedDict()
    for name, func in _funcs.items():
        decoded_bytes = _decode_bytes(unknown_bytes, func, name)
        if decoded_bytes:
            if decoded_bytes == unknown_bytes:
                no_difference.append(name)
            else:
                try:
                    unicode_str = decoded_bytes.decode()
                    output_dict[name] = unicode_str
                except UnicodeDecodeError:
                    output_dict[name] = repr(decoded_bytes)
        else:
            failed_encodings.append(name)
    ans={}
    if output_dict:
        column_chars = max([len(name) for name in output_dict.keys()])
        for name, output in output_dict.items():
            ans[name.ljust(column_chars)]=("{}".format(output))
    ans["Error"]=(", ".join(failed_encodings))
    ans["No change"]=(", ".join(no_difference))
    return ans



