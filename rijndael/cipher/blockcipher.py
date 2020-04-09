from rijndael.utils import cvt as util
from rijndael.utils import padding

MODE_ECB = 1
MODE_CBC = 2
MODE_CTR = 6

class BlockCipher():

    key_error_message = "Wrong key size"

    def __init__(self,key,mode,IV,counter,cipher_module,segment_size,args={}):
        self.key = key
        self.mode = mode
        self.cache = ''
        self.ed = None

        if 'keylen_valid' in dir(self):
         if not self.keylen_valid(key) and type(key) is not tuple:
                raise ValueError(self.key_error_message)

        if IV == None:
            self.IV = '\x00'*self.blocksize
        else:
            self.IV = IV

        self.cipher = cipher_module(self.key,**args)

        if mode == MODE_ECB:
            self.chain = ECB(self.cipher, self.blocksize)
        elif mode == MODE_CBC:
            if len(self.IV) != self.blocksize:
                raise Exception,"the IV length should be %i bytes"%self.blocksize
            self.chain = CBC(self.cipher, self.blocksize,self.IV)
        elif mode == MODE_CTR:
            if (counter == None) or  not callable(counter):
                raise Exception,"Supply a valid counter object for the CTR mode"
            self.chain = CTR(self.cipher,self.blocksize,counter)
        else:
                raise Exception,"Unknown chaining mode!"

    def encrypt(self,plaintext,n=''):
        self.ed = 'e'
        return self.chain.update(plaintext,'e')

    def decrypt(self,ciphertext,n=''):
        self.ed = 'd'

        return self.chain.update(ciphertext,'d')

    def final(self,padfct=padding.PKCS7):
        if self.ed == 'e':
            if self.mode in (MODE_CTR):
                dummy = '0'*(self.chain.totalbytes%self.blocksize)
            else: #ECB, CBC
                dummy = self.chain.cache
            pad = padfct(dummy,padding.PAD,self.blocksize)[len(dummy):]
            return self.chain.update(pad,'e')
        else:
            pass

class ECB:
    def __init__(self, codebook, blocksize):
        self.cache = ''
        self.codebook = codebook
        self.blocksize = blocksize

    def update(self, data, ed):
        output_blocks = []
        self.cache += data
        if len(self.cache) < self.blocksize:
            return ''
        for i in xrange(0, len(self.cache)-self.blocksize+1, self.blocksize):
            if ed == 'e':
                output_blocks.append(self.codebook.encrypt( self.cache[i:i + self.blocksize] ))
            else:
                output_blocks.append(self.codebook.decrypt( self.cache[i:i + self.blocksize] ))
        self.cache = self.cache[i+self.blocksize:]
        return ''.join(output_blocks)

class CBC:
    def __init__(self, codebook, blocksize, IV):
        self.IV = IV
        self.cache = ''
        self.codebook = codebook
        self.blocksize = blocksize

    def update(self, data, ed):
        if ed == 'e':
            encrypted_blocks = ''
            self.cache += data
            if len(self.cache) < self.blocksize:
                return ''
            for i in xrange(0, len(self.cache)-self.blocksize+1, self.blocksize):
                self.IV = self.codebook.encrypt(util.xorstring(self.cache[i:i+self.blocksize],self.IV))
                encrypted_blocks += self.IV
            self.cache = self.cache[i+self.blocksize:]
            return encrypted_blocks
        else:
            decrypted_blocks = ''
            self.cache += data
            if len(self.cache) < self.blocksize:
                return ''
            for i in xrange(0, len(self.cache)-self.blocksize+1, self.blocksize):
                plaintext = util.xorstring(self.IV,self.codebook.decrypt(self.cache[i:i + self.blocksize]))
                self.IV = self.cache[i:i + self.blocksize]
                decrypted_blocks+=plaintext
            self.cache = self.cache[i+self.blocksize:]
            return decrypted_blocks

class CTR:
    def __init__(self, codebook, blocksize, counter):
        self.codebook = codebook
        self.counter = counter
        self.blocksize = blocksize
        self.keystream = []
        self.totalbytes = 0

    def update(self, data, ed):
        n = len(data)
        blocksize = self.blocksize

        output = list(data)
        for i in xrange(n):
            if len(self.keystream) == 0:
                block = self.codebook.encrypt(self.counter())
                self.keystream = list(block)
            output[i] = chr(ord(output[i])^ord(self.keystream.pop(0)))
        self.totalbytes += len(output)
        return ''.join(output)
