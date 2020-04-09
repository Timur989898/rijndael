import random

PAD = 0
UNPAD = 1

def PKCS7(padData, direction, length=None):
        if direction == PAD:
            if length == None:
                raise ValueError,"Supply a valid length"
            return __PKCS7(padData, length)
        elif direction == UNPAD:
            return __PKCS7_unpad(padData)
        else:
            raise ValueError,"Supply a valid direction"


def __PKCS7 (toPad, length):
    amount = length - len(toPad)%length
    pattern = chr(amount)
    pad = pattern*amount
    return toPad + pad

def __PKCS7_unpad (padded):
    pattern = padded[-1]
    length = ord(pattern)
    if padded.endswith(pattern*length):
        return padded[:-length]
    else:
        return padded
        print 'error: padding pattern not recognized'

