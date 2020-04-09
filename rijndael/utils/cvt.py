def number2string(i):
    s=hex(i)[2:].rstrip('L')
    if len(s) % 2:
        s = '0' + s
    return s.decode('hex')

def number2string_N(i, N):
    s = '%0*x' % (N*2, i)
    return s.decode('hex')

def string2number(i):
    return int(i.encode('hex'),16)

def xorstring(a,b):
    assert len(a) == len(b)
    return number2string_N(string2number(a)^string2number(b), len(a))

class Counter(str):
    def __init__(self, initial_ctr):
        if not isinstance(initial_ctr, str):
            raise TypeError("nonce must be str")
        self.c = int(initial_ctr.encode('hex'), 16)
    def __call__(self):
        ctr = ("%032x" % (self.c,)).decode('hex')
        self.c += 1
        return ctr
