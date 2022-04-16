import unittest
from ctfbox.web import *
from ctfbox.thirdparty.phpserialize import serialize, unserialize


class TestWeb(unittest.TestCase):

    def test_hashAuth(self):
        self.assertEqual(hashAuth(answer="02fcf"), "16221")
        self.assertEqual(hashAuth(answer="d13ce", hashType=HashType.SHA1), "16221")
        self.assertEqual(hashAuth(answer="c907773", endIndex=7, threadNum=50), "500000")
        self.assertEqual(hashAuth(answer="59e711d", endIndex=7, maxRange=2000000), "1000001")
        self.assertEqual(hashAuth(answer="ba25a77", prefix="WTF"), "233")

    def test_get_flask_pin(self):
        self.assertEqual(get_flask_pin("kingkk", "/home/kingkk/.local/lib/python3.5/site-packages/flask/app.py",
                                       "00:0c:29:e5:45:6a", "19949f18ce36422da1402b3e3fe53008"), "169-851-075")
        self.assertEqual(get_flask_pin("ctf", "/usr/local/lib/python3.8/site-packages/flask/app.py",
                                       "02:42:ac:15:00:03", "1cc402dd0e11d5ae18db04a6de87223d", 200), "943-044-403")

    def test_httpraw(self):
        # test get request and headers
        request = httpraw(b'''
GET /get HTTP/1.1
Host: httpbin.org
User-Agent: curl/7.68.0
Accept: */*''', send=False)
        self.assertEqual(request.url, "http://httpbin.org/get")
        self.assertEqual(request.method, b"GET")
        self.assertEqual(request.headers["User-Agent"], "curl/7.68.0")

        # test POST application/x-www-form-urlencoded rquest
        request = httpraw(b'''
POST /post HTTP/1.1
Host: httpbin.org
User-Agent: curl/7.68.0
Accept: */*

money=1000&message=success
''', send=False)
        self.assertEqual(request.url, "http://httpbin.org/post")
        self.assertEqual(request.method, b"POST")
        self.assertEqual(request.data, {"money": "1000", "message": "success"})

        # test POST application/json rquest
        request = httpraw(b'''
POST /post HTTP/1.1
Host: httpbin.org
User-Agent: curl/7.68.0
Accept: */*

{"money": "1000", "message": "success"}
''', send=False)
        self.assertEqual(request.url, "http://httpbin.org/post")
        self.assertEqual(request.method, b"POST")
        self.assertEqual(request.headers["Content-Type"], "application/json")
        self.assertEqual(request.data, b'{"money": "1000", "message": "success"}')

        # test POST multipart/form-data rquest
        request = httpraw(b'''
POST /post HTTP/1.1
Host: httpbin.org
User-Agent: curl/7.68.0
Accept: */*
Content-Type: multipart/form-data

--------------------------bb1d590c64102511
Content-Disposition: attachment; name="file"; filename="a.txt"
Content-Type: text/plain

Syclover{test_od_parse}
--------------------------bb1d590c64102511--

--------------------------bb1d590c64102512
Content-Disposition: attachment; name="arg";

Syclover
--------------------------bb1d590c64102512--
''', send=False)
        self.assertEqual(request.url, "http://httpbin.org/post")
        self.assertEqual(request.method, b"POST")
        self.assertEqual(request.files, {b'file': ('a.txt', b'Syclover{test_od_parse}', 'text/plain')})
        self.assertEqual(request.data, {b"arg": b"Syclover"})

    def test_php_serialize_escape_s2l(self):
        class User(object):
            def __init__(self, username, password):
                self.username = username
                self.password = password

        payload = 's:8:"password";s:9:"123456.00"'
        # diff_len = 1
        payload_dict = php_serialize_escape_s2l('!', '@@', payload)
        u = User(payload_dict.get('insert_data'), '123456')
        s = serialize(u).replace(b'!', b'@@')
        s = s.decode()
        d = unserialize(s)._asdict()
        self.assertEqual('123456.00', d['password'])

        # diff_len = 2
        payload_dict = php_serialize_escape_s2l('!', '@@@', payload)
        u = User(payload_dict.get('insert_data'), '123456')
        s = serialize(u).replace(b'!', b'@@@')
        s = s.decode()
        d = unserialize(s)._asdict()
        self.assertEqual('123456.00', d['password'])

        # diff_len = 5
        class User(object):
            def __init__(self, username, password):
                self.username = username
                self.password = password
                self.sign = 'hello'

        payload_dict = php_serialize_escape_s2l('!', '@@@@@', payload, True)
        u = User(payload_dict.get('insert_data'), '123456')
        s = serialize(u).replace(b'!', b'@@@@@')
        s = s.decode()
        d = unserialize(s)._asdict()
        self.assertEqual('123456.00', d['password'])

    def test_php_serialize_escape_l2s(self):
        class User(object):
            def __init__(self, username, password):
                self.username = username
                self.password = password
                self.sign = 'hello'

        payload = 's:8:"password";s:4:"test";s:4:"sign";s:6:"hacker"'
        # diff_len = 1
        payload_dict = php_serialize_escape_l2s('yy', 'x', payload)
        u = User(payload_dict.get('populoate_data'),
                 payload_dict.get('insert_data'))
        s = serialize(u).replace(b'yy', b'x')
        s = s.decode()
        d = unserialize(s)._asdict()
        self.assertEqual('test', d['password'])
        self.assertEqual('hacker', d['sign'])

        # diff_len = 2
        payload_dict = php_serialize_escape_l2s('yyy', 'x', payload, True)
        u = User(payload_dict.get('populate_data'),
                 payload_dict.get('insert_data'))
        s = serialize(u).replace(b'yyy', b'x')
        s = s.decode()
        d = unserialize(s)._asdict()
        self.assertEqual('test', d['password'])
        self.assertEqual('hacker', d['sign'])

        # diff_len = 5
        payload_dict = php_serialize_escape_l2s('yyyyyy', 'x', payload, True)
        u = User(payload_dict.get('populate_data'),
                 payload_dict.get('insert_data'))
        s = serialize(u).replace(b'yyyyyy', b'x')
        s = s.decode()
        d = unserialize(s)._asdict()
        self.assertEqual('test', d['password'])
        self.assertEqual('hacker', d['sign'])


if __name__ == '__main__':
    unittest.main()
