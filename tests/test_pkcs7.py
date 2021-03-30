#! -*- coding: utf-8 -*-

from builtins import chr
from builtins import range
import unittest
import scapy_ssl_tls.pkcs7 as pkcs7


class TestPKCS7Encoder(unittest.TestCase):

    def setUp(self):
        self.pkcs7 = pkcs7.PKCS7Encoder()
        unittest.TestCase.setUp(self)

    def test_pkcs7_encoder_returns_expected_padding_on_short_block(self):
        data = b"ABCDE"
        pkcs7_data = self.pkcs7.encode(data)
        self.assertEqual(len(pkcs7_data), self.pkcs7.k)
        self.assertEqual(
            pkcs7_data[len(data):],
            chr(self.pkcs7.k - len(data)).encode() * (self.pkcs7.k - len(data)))

    def test_pkcs7_padding_only_is_returned_on_get_padding_call(self):
        data = b"A" * 16
        pkcs7_padding = self.pkcs7.get_padding(data)
        self.assertEqual(len(pkcs7_padding), self.pkcs7.k)
        self.assertEqual(chr(len(pkcs7_padding)).encode() * len(pkcs7_padding), pkcs7_padding)
        self.assertEqual((data + pkcs7_padding), self.pkcs7.encode(data))

    def test_pkcs7_encode_decode(self):
        data = b'X'
        for length in range(self.pkcs7.k * 2 + 1):
            pkcs7_data = self.pkcs7.encode(data * length)
            self.assertEqual(len(pkcs7_data) % self.pkcs7.k, 0)
            self.assertEqual(self.pkcs7.decode(pkcs7_data), data * length)

    def test_pkcs7_raises_valueerror_on_invalid_padding(self):
        data = b"X"
        pkcs7_data = self.pkcs7.encode(data)
        pkcs7_data = pkcs7_data[:-1] + b'\xff'
        with self.assertRaises(ValueError):
            self.pkcs7.decode(pkcs7_data)
