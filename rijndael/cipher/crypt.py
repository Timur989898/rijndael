from rijndael.cipher.blockcipher import *
from rijndael.cipher.method import rijndael


def new(key,mode=MODE_ECB,IV=None,counter=None,segment_size=None,blocksize=None):
    return python_Rijndael(key,mode,IV,counter,blocksize,segment_size)

class python_Rijndael(BlockCipher):
    key_error_message = ("Key should be 128, 192 or 256 bits")

    def __init__(self,key,mode,IV,counter,blocksize,segment_size):
        if blocksize not in (16,24,32):
                raise ValueError("Blocksize should be 16, 24 or 32")
        cipher_module = rijndael
        args = {'block_size':blocksize}
        self.blocksize = blocksize
        BlockCipher.__init__(self,key,mode,IV,counter,cipher_module,segment_size,args)

    def keylen_valid(self,key):
        return len(key) in (16,24,32)
