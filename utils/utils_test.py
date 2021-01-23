import unittest
import sys
from utils import *


class TestUtils(unittest.TestCase):

    def test_url_encode(self):
        self.assertEqual(url_encode("你好"), r"%E4%BD%A0%E5%A5%BD")
        self.assertEqual(url_encode(" +/"), r"+%2B%2F")

    def test_url_decode(self):
        self.assertEqual(url_decode(r"%E4%BD%A0%E5%A5%BD"), "你好")
        self.assertEqual(url_decode(r"+%2B%2F"), " +/")

    def test_base64_decode(self):
        self.assertEqual(base64_decode("ZXhhbXBsZQ=="), "example")

    def test_base64_encode(self):
        self.assertEqual(base64_encode("example"), "ZXhhbXBsZQ==")

    def test_bin2hex(self):
        self.assertEqual(bin2hex("example"), "6578616d706c65")

    def test_hex2bin(self):
        self.assertEqual(hex2bin("6578616d706c65"), "example")

    def test_sha1(self):
        self.assertEqual(
            sha1("example"), "c3499c2729730a7f807efb8676a92dcb6f8a3f8f")

    def test_sha256(self):
        self.assertEqual(sha256("example"),
                         "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c")

    def test_md5(self):
        self.assertEqual(md5("example"), "1a79a4d60de6718e8e5b326e338ae533")

    def test_random_int(self):
        v = random_int(0, 10)
        self.assertTrue(0 <= v <= 10)
        v = random_int(2, 1)
        self.assertEqual(v, 0)

    def test_random_string(self):
        v = random_string()
        self.assertTrue(len(v), 32)

        v = random_string(16)
        self.assertTrue(len(v), 16)

        v = random_string(32, "1234567890")
        for s in v:
            self.assertIn(s, "1234567890")

        v = random_string(32, "a")
        self.assertTrue(v, "a" * 32)

    def test_jwt_decode(self):
        token_test = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'
        self.assertTrue(
            b'{"alg":"HS256","typ":"JWT"}-{"sub":"1234567890","name":"John Doe","iat":1516239022}', jwt_decode(token_test))

        token_test = 'eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJ0ZXN0IjoiZXhhbXBsZSJ9'
        self.assertTrue(
            b'{"alg":"None","typ":"JWT"}-{"test":"example"}', jwt_decode(token_test))

    def test_jwt_encode(self):
        header_example = {
            'alg': 'None',
            'typ': 'JWT'
        }
        payload_example = {
            'test': 'example'
        }
        self.assertTrue('eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJ0ZXN0IjoiZXhhbXBsZSJ9', jwt_encode(
            header_example, payload_example))

        header_example = {
            'alg': 'HS256',
            'typ': 'JWT'
        }
        payload_example = {
            'test': 'example'
        }
        result = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoiZXhhbXBsZSJ9.FtMkXnl-4jMLu7qYjx2VeyiGH9R_4urRgHUYGXmq8mE'
        self.assertTrue(result, jwt_encode(
            header_example, payload_example, '123456', 'HS256'))

    def test__pN(self):
        # when passing number and sign that dosenot match, 
        # it shall get error from python builtin module struct
        self.assertEqual(b'\xcd\xab', p16(0xabcd))
        self.assertEqual(b'\xab\xcd', p16(0xabcd, endianness='big'))
        self.assertEqual(b'\x15\xcd[\x07', p32(123456789))
        self.assertEqual(b'\x07[\xcd\x15', p32(123456789, endianness='big'))

    def test__uN(self):
        self.assertEqual(0xcdab, u16(b'\xab\xcd'))
        self.assertEqual(0xabcd, u16(b'\xab\xcd', endianness='big'))
        self.assertEqual(0x00ab, u16(b'\xab'))
        self.assertEqual(0x61626364, u32(b'dcba'))


if __name__ == '__main__':
    unittest.main()
