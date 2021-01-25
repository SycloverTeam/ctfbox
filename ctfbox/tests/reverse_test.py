import unittest
from ctfbox.reverse import *


class TestReverse(unittest.TestCase):
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
