import unittest

from rijndael.utils import cvt as util
from rijndael.cipher.crypt import new
from rijndael.cipher.blockcipher import MODE_CTR
from rijndael.cipher.blockcipher import MODE_ECB
from rijndael.cipher.blockcipher import MODE_CBC


class RijndaelEqualityTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        self.key = 'f91qwo45yeh4ir89'
        self.iv = '947d0eruj59q0124'
        self.blocksize = 16

    def test_sanity_ctr_mode(self):
        string = 'f34481ec3cc627bacd5dc3fb08f273e6'
        rijndael_e = new(self.key, MODE_CTR, self.iv, util.Counter('16'), blocksize=self.blocksize)
        encrypted = rijndael_e.encrypt(string)
        rijndael_d = new(self.key, MODE_CTR, self.iv, util.Counter('16'), blocksize=self.blocksize)
        decypted = rijndael_d.decrypt(encrypted)
        self.assertEquals(string, decypted)

    def test_sanity_cbc_mode(self):
        string = 'f34481ec3cc627bacd5dc3fb08f273e6'
        rijndael_e = new(self.key, MODE_CBC, self.iv, blocksize=self.blocksize)
        encrypted = rijndael_e.encrypt(string)
        rijndael_d = new(self.key, MODE_CBC, self.iv, blocksize=self.blocksize)
        decypted = rijndael_d.decrypt(encrypted)
        self.assertEquals(string, decypted)

    def test_sanity_ecb_mode(self):
        string = 'f34481ec3cc627bacd5dc3fb08f273e6'
        rijndael_e = new(self.key, MODE_ECB, self.iv, blocksize=self.blocksize)
        encrypted = rijndael_e.encrypt(string)
        rijndael_d = new(self.key, MODE_ECB, self.iv, blocksize=self.blocksize)
        decypted = rijndael_d.decrypt(encrypted)
        self.assertEquals(string, decypted)
