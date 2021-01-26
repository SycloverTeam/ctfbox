import unittest
from ctfbox.web import *
from ctfbox.thirdparty.phpserialize import serialize, unserialize


class TestWeb(unittest.TestCase):
    def test_get_flask_pin(self):
        self.assertEqual(get_flask_pin("kingkk", "/home/kingkk/.local/lib/python3.5/site-packages/flask/app.py",
                                       "00:0c:29:e5:45:6a", "19949f18ce36422da1402b3e3fe53008"), "169-851-075")

    def test_php_serialize_escape_s2l(self):
        class User(object):
            def __init__(self, username, password):
                self.username = username
                self.password = password

        payload = 's:8:"password";s:9:"123456.00"'
        # diff_len = 1
        payload_dict = php_serialize_escape_s2l('x', 'yy', payload)
        u = User(payload_dict.get('insert_data'), '123456')
        s = serialize(u).replace(b'x', b'yy')
        s = s.decode()
        d = unserialize(s)._asdict()
        self.assertEqual('123456.00', d['password'])

        # diff_len = 2
        payload_dict = php_serialize_escape_s2l('x', 'yyy', payload)
        u = User(payload_dict.get('insert_data'), '123456')
        s = serialize(u).replace(b'x', b'yyy')
        s = s.decode()
        d = unserialize(s)._asdict()
        self.assertEqual('123456.00', d['password'])

        # diff_len = 5
        class User(object):
            def __init__(self, username, password):
                self.username = username
                self.password = password
                self.sign = 'hello'

        payload_dict = php_serialize_escape_s2l('x', 'yyyyyy', payload, True)
        u = User(payload_dict.get('insert_data'), '123456')
        s = serialize(u).replace(b'x', b'yyyyyy')
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
        u = User(payload_dict.get('populoate_data'), payload_dict.get('insert_data'))
        s = serialize(u).replace(b'yy', b'x')
        s = s.decode()
        d = unserialize(s)._asdict()
        self.assertEqual('test', d['password'])
        self.assertEqual('hacker', d['sign'])

        # diff_len = 2
        payload_dict = php_serialize_escape_l2s('yyy', 'x', payload, True)
        u = User(payload_dict.get('populate_data'), payload_dict.get('insert_data'))
        s = serialize(u).replace(b'yyy', b'x')
        s = s.decode()
        d = unserialize(s)._asdict()
        self.assertEqual('test', d['password'])
        self.assertEqual('hacker', d['sign'])

        # diff_len = 5
        payload_dict = php_serialize_escape_l2s('yyyyyy', 'x', payload, True)
        u = User(payload_dict.get('populate_data'), payload_dict.get('insert_data'))
        s = serialize(u).replace(b'yyyyyy', b'x')
        s = s.decode()
        d = unserialize(s)._asdict()
        self.assertEqual('test', d['password'])
        self.assertEqual('hacker', d['sign'])


if __name__ == '__main__':
    unittest.main()
