import unittest
from ctfbox.web import *


class TestWeb(unittest.TestCase):
    def test_get_flask_pin(self):
        self.assertEqual(get_flask_pin("kingkk", "/home/kingkk/.local/lib/python3.5/site-packages/flask/app.py",
                                       "00:0c:29:e5:45:6a", "19949f18ce36422da1402b3e3fe53008"), "169-851-075")


if __name__ == '__main__':
    unittest.main()
